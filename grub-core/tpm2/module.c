/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2022 Microsoft Corporation
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/dl.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/protector.h>
#include <grub/tpm2/buffer.h>
#include <grub/tpm2/internal/args.h>
#include <grub/tpm2/mu.h>
#include <grub/tpm2/tpm2.h>

GRUB_MOD_LICENSE ("GPLv3+");

typedef enum grub_tpm2_protector_mode
{
  GRUB_TPM2_PROTECTOR_MODE_UNSET,
  GRUB_TPM2_PROTECTOR_MODE_SRK,
  GRUB_TPM2_PROTECTOR_MODE_NV
} grub_tpm2_protector_mode_t;

struct grub_tpm2_protector_context
{
  grub_tpm2_protector_mode_t mode;
  grub_uint8_t pcrs[TPM_MAX_PCRS];
  grub_uint8_t pcr_count;
  TPM_ALG_ID asymmetric;
  TPM_ALG_ID bank;
  const char *keyfile;
  TPM_HANDLE srk;
  TPM_HANDLE nv;
};

static const struct grub_arg_option grub_tpm2_protector_init_cmd_options[] =
  {
    /* Options for all modes */
    {
      .longarg  = "mode",
      .shortarg = 'm',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Unseal key using SRK ('srk') (default) or retrieve it from an NV "
           "Index ('nv')."),
    },
    {
      .longarg  = "pcrs",
      .shortarg = 'p',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Comma-separated list of PCRs used to authorize key release "
           "(e.g., '7,11', default is 7."),
    },
    {
      .longarg  = "bank",
      .shortarg = 'b',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Bank of PCRs used to authorize key release: "
           "SHA1, SHA256 (default), or SHA384."),
    },
    /* SRK-mode options */
    {
      .longarg  = "keyfile",
      .shortarg = 'k',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Required in SRK mode, path to the sealed key file to unseal using "
           "the TPM (e.g., (hd0,gpt1)/boot/grub2/sealed_key)."),
    },
    {
      .longarg  = "srk",
      .shortarg = 's',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("In SRK mode, the SRK handle if the SRK is persistent "
           "(default is 0x81000001)."),
    },
    {
      .longarg  = "asymmetric",
      .shortarg = 'a',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("In SRK mode, the type of SRK: RSA (default) or ECC."),
    },
    /* NV Index-mode options */
    {
      .longarg  = "nvindex",
      .shortarg = 'n',
      .flags    = 0,
      .arg      = NULL,
      .type     = ARG_TYPE_STRING,
      .doc      =
        N_("Required in NV Index mode, the NV handle to read which must "
           "readily exist on the TPM and which contains the key."),
    },
    /* End of list */
    {0, 0, 0, 0, 0, 0}
  };

static grub_extcmd_t grub_tpm2_protector_init_cmd;
static grub_extcmd_t grub_tpm2_protector_clear_cmd;
static struct grub_tpm2_protector_context grub_tpm2_protector_ctx = { 0 };

static grub_err_t
grub_tpm2_protector_srk_read_keyfile (const char *filepath, void **buffer,
                                      grub_size_t *buffer_size)
{
  grub_file_t sealed_key_file;
  grub_off_t sealed_key_size;
  void *sealed_key_buffer;
  grub_off_t sealed_key_read;

  sealed_key_file = grub_file_open (filepath, GRUB_FILE_TYPE_NONE);
  if (!sealed_key_file)
    {
      grub_dprintf ("tpm2", "Could not open sealed key file.\n");
      /* grub_file_open sets grub_errno on error, and if we do no unset it,
       * future calls to grub_file_open will fail (and so will anybody up the
       * stack who checks the value, if any). */
      grub_errno = GRUB_ERR_NONE;
      return GRUB_ERR_FILE_NOT_FOUND;
    }

  sealed_key_size = grub_file_size (sealed_key_file);
  if (!sealed_key_size)
    {
      grub_dprintf ("tpm2", "Could not read sealed key file size.\n");
      grub_file_close (sealed_key_file);
      return GRUB_ERR_OUT_OF_RANGE;
    }

  sealed_key_buffer = grub_malloc (sealed_key_size);
  if (!sealed_key_buffer)
    {
      grub_dprintf ("tpm2", "Could not allocate buffer for sealed key.\n");
      grub_file_close (sealed_key_file);
      return GRUB_ERR_OUT_OF_MEMORY;
    }

  sealed_key_read = grub_file_read (sealed_key_file, sealed_key_buffer,
                                    sealed_key_size);
  if (sealed_key_read != sealed_key_size)
    {
      grub_dprintf ("tpm2", "Could not retrieve sealed key file contents.\n");
      grub_free (sealed_key_buffer);
      grub_file_close (sealed_key_file);
      return GRUB_ERR_FILE_READ_ERROR;
    }

  grub_file_close (sealed_key_file);

  *buffer = sealed_key_buffer;
  *buffer_size = sealed_key_size;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_srk_unmarshal_keyfile (void *sealed_key,
                                           grub_size_t sealed_key_size,
                                           TPM2_SEALED_KEY *sk)
{
  struct grub_tpm2_buffer buf;

  grub_tpm2_buffer_init (&buf);
  if (sealed_key_size > buf.cap)
    {
      grub_dprintf ("tpm2", "Sealed key file is larger than decode buffer "
                            "(%lu vs %lu bytes).\n", sealed_key_size, buf.cap);
      return GRUB_ERR_BAD_ARGUMENT;
    }

  grub_memcpy (buf.data, sealed_key, sealed_key_size);
  buf.size = sealed_key_size;

  grub_tpm2_mu_TPM2B_PUBLIC_Unmarshal (&buf, &sk->public);
  grub_tpm2_mu_TPM2B_Unmarshal (&buf, (TPM2B *)&sk->private);

  if (buf.error)
    {
      grub_dprintf ("tpm2", "Could not unmarshal sealed key file, it is likely "
                            "malformed.\n");
      return GRUB_ERR_BAD_ARGUMENT;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_srk_get (const struct grub_tpm2_protector_context *ctx,
                             TPM_HANDLE *srk)
{
  TPM_RC rc;
  TPM2B_PUBLIC public;
  TPMS_AUTH_COMMAND authCommand = { 0 };
  TPM2B_SENSITIVE_CREATE inSensitive = { 0 };
  TPM2B_PUBLIC inPublic = { 0 };
  TPM2B_DATA outsideInfo = { 0 };
  TPML_PCR_SELECTION creationPcr = { 0 };
  TPM2B_PUBLIC outPublic = { 0 };
  TPM2B_CREATION_DATA creationData = { 0 };
  TPM2B_DIGEST creationHash = { 0 };
  TPMT_TK_CREATION creationTicket = { 0 };
  TPM2B_NAME srkName = { 0 };
  TPM_HANDLE srkHandle;

  /* Find SRK */
  rc = TPM2_ReadPublic (ctx->srk, NULL, &public);
  if (rc == TPM_RC_SUCCESS)
    {
      *srk = ctx->srk;
      return GRUB_ERR_NONE;
    }

  /* The handle exists but its public area could not be read. */
  if ((rc & ~TPM_RC_N_MASK) != TPM_RC_HANDLE)
    {
      grub_dprintf ("tpm2", "The SRK handle (0x%x) exists on the TPM but its "
                            "public area could not be read (TPM2_ReadPublic "
                            "failed with TSS/TPM error %u).\n", ctx->srk, rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  /* Create SRK */
  authCommand.sessionHandle = TPM_RS_PW;
  inPublic.publicArea.type = ctx->asymmetric;
  inPublic.publicArea.nameAlg  = TPM_ALG_SHA256;
  inPublic.publicArea.objectAttributes.restricted = 1;
  inPublic.publicArea.objectAttributes.userWithAuth = 1;
  inPublic.publicArea.objectAttributes.decrypt = 1;
  inPublic.publicArea.objectAttributes.fixedTPM = 1;
  inPublic.publicArea.objectAttributes.fixedParent = 1;
  inPublic.publicArea.objectAttributes.sensitiveDataOrigin = 1;
  inPublic.publicArea.objectAttributes.noDA = 1;

  if (ctx->asymmetric == TPM_ALG_RSA)
    {
      inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
      inPublic.publicArea.parameters.rsaDetail.exponent = 0;
    }
  else if (ctx->asymmetric == TPM_ALG_ECC)
    {
      inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
      inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
      inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
      inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
      inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
      inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    }
  else
    return GRUB_ERR_BAD_ARGUMENT;

  rc = TPM2_CreatePrimary (TPM_RH_OWNER, &authCommand, &inSensitive, &inPublic,
                           &outsideInfo, &creationPcr, &srkHandle, &outPublic,
                           &creationData, &creationHash, &creationTicket,
                           &srkName, NULL);
  if (rc != TPM_RC_SUCCESS)
    {
      grub_dprintf ("tpm2", "Could not create SRK (TPM2_CreatePrimary failed "
                            "with TSS/TPM error %u).\n", rc);
      return GRUB_ERR_BAD_DEVICE;
    }

  *srk = srkHandle;

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_srk_recover (const struct grub_tpm2_protector_context *ctx,
                                 grub_uint8_t **key, grub_size_t *key_size)
{
  TPM_RC rc;
  TPM2_SEALED_KEY sealed_key;
  void *sealed_key_bytes;
  grub_size_t sealed_key_size;
  TPM_HANDLE srk_handle;
  TPM2B_NONCE nonceCaller = { 0 };
  TPM2B_ENCRYPTED_SECRET salt = { 0 };
  TPMT_SYM_DEF symmetric = { 0 };
  TPM2B_NONCE nonceTPM = { 0 };
  TPMI_SH_AUTH_SESSION session;
  TPML_PCR_SELECTION pcrSel = {
    .count = 1,
    .pcrSelections = {
      {
        .hash = ctx->bank,
        .sizeOfSelect = 3,
        .pcrSelect = { 0 }
      },
    }
  };
  TPMS_AUTH_COMMAND authCmd = { 0 };
  TPM_HANDLE sealed_key_handle;
  TPM2B_NAME name;
  TPMS_AUTH_RESPONSE authResponse;
  TPM2B_SENSITIVE_DATA data;
  grub_uint8_t *key_out;
  grub_uint8_t i;
  grub_err_t err;

  /* Retrieve Sealed Key */
  err = grub_tpm2_protector_srk_read_keyfile (ctx->keyfile, &sealed_key_bytes,
                                              &sealed_key_size);
  if (err)
    return grub_error (err, N_("Failed to read key file %s"), ctx->keyfile);

  err = grub_tpm2_protector_srk_unmarshal_keyfile (sealed_key_bytes,
                                                   sealed_key_size,
                                                   &sealed_key);
  if (err)
    {
      grub_error (err, N_("Failed to unmarshal key, ensure the key file is in "
                          "TPM wire format"));
      goto exit1;
    }

  /* Get SRK */
  err = grub_tpm2_protector_srk_get (ctx, &srk_handle);
  if (err)
    {
      grub_error (err, N_("Failed to retrieve the SRK"));
      goto exit1;
    }

  err = GRUB_ERR_BAD_DEVICE;

  /* Start Auth Session */
  nonceCaller.size = TPM_SHA256_DIGEST_SIZE;
  symmetric.algorithm = TPM_ALG_NULL;

  rc = TPM2_StartAuthSession (TPM_RH_NULL, TPM_RH_NULL, 0, &nonceCaller, &salt,
                              TPM_SE_POLICY, &symmetric, TPM_ALG_SHA256,
                              &session, &nonceTPM, 0);
  if (rc)
    {
      grub_error (err, N_("Failed to start auth session (TPM2_StartAuthSession "
                          "failed with TSS/TPM error %u)"), rc);
      goto exit2;
    }

  /* Policy PCR */
  for (i = 0; i < ctx->pcr_count; i++)
    pcrSel
      .pcrSelections[0]
      .pcrSelect[TPM2_PCR_TO_SELECT(ctx->pcrs[i])]
        |= TPM2_PCR_TO_BIT(ctx->pcrs[i]);

  rc = TPM2_PolicyPCR (session, NULL, NULL, &pcrSel, NULL);
  if (rc)
    {
      grub_error (err, N_("Failed to submit PCR policy (TPM2_PolicyPCR failed "
                          "with TSS/TPM error %u)"), rc);
      goto exit3;
    }

  /* Load Sealed Key */
  authCmd.sessionHandle = TPM_RS_PW;
  rc = TPM2_Load (srk_handle, &authCmd, &sealed_key.private, &sealed_key.public,
                  &sealed_key_handle, &name, &authResponse);
  if (rc)
    {
      grub_error (err, N_("Failed to load sealed key (TPM2_Load failed with "
                          "TSS/TPM error %u)"), rc);
      goto exit3;
    }

  /* Unseal Sealed Key */
  authCmd.sessionHandle = session;
  grub_memset (&authResponse, 0, sizeof (authResponse));

  rc = TPM2_Unseal (sealed_key_handle, &authCmd, &data, &authResponse);
  if (rc)
    {
      grub_error (err, N_("Failed to unseal sealed key (TPM2_Unseal failed "
                          "with TSS/TPM error %u)"), rc);
      goto exit4;
    }

  /* Epilogue */
  key_out = grub_malloc (data.size);
  if (!key_out)
    {
      err = GRUB_ERR_OUT_OF_MEMORY;
      grub_error (err, N_("No memory left to allocate unlock key buffer"));
      goto exit4;
    }

  grub_memcpy (key_out, data.buffer, data.size);

  *key = key_out;
  *key_size = data.size;

  err = GRUB_ERR_NONE;

exit4:
  TPM2_FlushContext (sealed_key_handle);

exit3:
  TPM2_FlushContext (session);

exit2:
  TPM2_FlushContext (srk_handle);

exit1:
  grub_free (sealed_key_bytes);
  return err;
}

static grub_err_t
grub_tpm2_protector_nv_recover (const struct grub_tpm2_protector_context *ctx,
                                grub_uint8_t **key, grub_size_t *key_size)
{
  (void)ctx;
  (void)key;
  (void)key_size;

  return grub_error (GRUB_ERR_NOT_IMPLEMENTED_YET,
                     N_("NV Index mode is not implemented yet"));
}

static grub_err_t
grub_tpm2_protector_recover (const struct grub_tpm2_protector_context *ctx,
                             grub_uint8_t **key, grub_size_t *key_size)
{
  switch (ctx->mode)
    {
    case GRUB_TPM2_PROTECTOR_MODE_SRK:
      return grub_tpm2_protector_srk_recover (ctx, key, key_size);
    case GRUB_TPM2_PROTECTOR_MODE_NV:
      return grub_tpm2_protector_nv_recover (ctx, key, key_size);
    default:
      return GRUB_ERR_BAD_ARGUMENT;
    }
}

static grub_err_t
grub_tpm2_protector_recover_key (grub_uint8_t **key, grub_size_t *key_size)
{
  grub_err_t err;

  /* Expect a call to tpm2_protector_init before anybody tries to use us */
  if (grub_tpm2_protector_ctx.mode == GRUB_TPM2_PROTECTOR_MODE_UNSET)
    return grub_error (GRUB_ERR_INVALID_COMMAND,
                       N_("Cannot use TPM2 key protector without initializing "
                          "it, call tpm2_protector_init first"));

  if (!key)
    return GRUB_ERR_BAD_ARGUMENT;

  err = grub_tpm2_protector_recover (&grub_tpm2_protector_ctx, key, key_size);
  if (err)
    return err;

  return GRUB_ERR_NONE;
}


static grub_err_t
grub_tpm2_protector_check_args (struct grub_tpm2_protector_context *ctx)
{
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_UNSET)
    ctx->mode = GRUB_TPM2_PROTECTOR_MODE_SRK;

  /* Checks for SRK mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && !ctx->keyfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In SRK mode, a key file must be specified: "
                          "--keyfile or -k"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK && ctx->nv)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In SRK mode, an NV Index cannot be specified"));

  /* Checks for NV mode */
  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && !ctx->nv)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an NV Index must be specified: "
                           "--nvindex or -n"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->keyfile)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, a keyfile cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->srk)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an SRK cannot be specified"));

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_NV && ctx->asymmetric)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("In NV Index mode, an asymmetric key type cannot be "
                          "specified"));

  /* Defaults assignment */
  if (!ctx->bank)
    ctx->bank = TPM_ALG_SHA256;

  if (!ctx->pcr_count)
    {
      ctx->pcrs[0] = 7;
      ctx->pcr_count = 1;
    }

  if (ctx->mode == GRUB_TPM2_PROTECTOR_MODE_SRK)
    {
      if (!ctx->srk)
        ctx->srk = TPM2_SRK_HANDLE;

      if (!ctx->asymmetric)
        ctx->asymmetric = TPM_ALG_RSA;
    }

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_parse_keyfile (const char *value, const char **keyfile)
{
  if (grub_strlen (value) == 0)
    return GRUB_ERR_BAD_ARGUMENT;

  *keyfile = grub_strdup (value);
  if (!*keyfile)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
                       N_("No memory to duplicate keyfile path"));

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_parse_mode (const char *value,
                                grub_tpm2_protector_mode_t *mode)
{
  if (grub_strcmp (value, "srk") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_SRK;
  else if (grub_strcmp (value, "nv") == 0)
    *mode = GRUB_TPM2_PROTECTOR_MODE_NV;
  else
    return grub_error (GRUB_ERR_OUT_OF_RANGE,
                       N_("Value '%s' is not a valid TPM2 key protector mode"),
                       value);

  return GRUB_ERR_NONE;
}

static grub_err_t
grub_tpm2_protector_init_cmd_handler (grub_extcmd_context_t ctxt, int argc,
                                 char **args __attribute__ ((unused)))
{
  struct grub_arg_list *state = ctxt->state;
  grub_err_t err;

  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("The TPM2 key protector does not accept any "
                          "non-option arguments (i.e., like -o and/or --option "
                          "only)"));

  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  if (state[0].set)  /* mode */
    {
      err = grub_tpm2_protector_parse_mode (state[0].arg,
                                            &grub_tpm2_protector_ctx.mode);
      if (err)
        return err;
    }

  if (state[1].set)  /* pcrs */
    {
      err = grub_tpm2_protector_parse_pcrs (state[1].arg,
                                            grub_tpm2_protector_ctx.pcrs,
                                            &grub_tpm2_protector_ctx.pcr_count);
      if (err)
        return err;
    }

  if (state[2].set)  /* bank */
    {
      err = grub_tpm2_protector_parse_bank (state[2].arg,
                                            &grub_tpm2_protector_ctx.bank);
      if (err)
        return err;
    }

  if (state[3].set)  /* keyfile */
    {
      err = grub_tpm2_protector_parse_keyfile (state[3].arg,
                                               &grub_tpm2_protector_ctx.keyfile);
      if (err)
        return err;
    }

  if (state[4].set)  /* srk */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[4].arg,
                                                  &grub_tpm2_protector_ctx.srk);
      if (err)
        return err;
    }

  if (state[5].set)  /* asymmetric */
    {
      err = grub_tpm2_protector_parse_asymmetric (state[5].arg,
                                                  &grub_tpm2_protector_ctx.asymmetric);
      if (err)
        return err;
    }

  if (state[6].set)  /* nvindex */
    {
      err = grub_tpm2_protector_parse_tpm_handle (state[6].arg,
                                                  &grub_tpm2_protector_ctx.nv);
      if (err)
        return err;
    }

  err = grub_tpm2_protector_check_args (&grub_tpm2_protector_ctx);

  /* This command only initializes the protector, so nothing else to do. */

  return err;
}

static grub_err_t
grub_tpm2_protector_clear_cmd_handler (grub_extcmd_context_t ctxt __attribute__ ((unused)),
                                       int argc,
                                       char **args __attribute__ ((unused)))
{
  if (argc)
    return grub_error (GRUB_ERR_BAD_ARGUMENT,
                       N_("tpm2_key_protector_clear accepts no arguments"));

  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  return GRUB_ERR_NONE;
}

static struct grub_key_protector grub_tpm2_key_protector =
  {
    .name = "tpm2",
    .recover_key = grub_tpm2_protector_recover_key
  };

GRUB_MOD_INIT (tpm2)
{
  grub_tpm2_protector_init_cmd =
    grub_register_extcmd ("tpm2_key_protector_init",
                          grub_tpm2_protector_init_cmd_handler, 0,
                          N_("[-m mode] "
                             "[-p pcr_list] "
                             "[-b pcr_bank] "
                             "[-k sealed_key_file_path] "
                             "[-s srk_handle] "
                             "[-a asymmetric_key_type] "
                             "[-n nv_index]"),
                          N_("Initialize the TPM2 key protector."),
                          grub_tpm2_protector_init_cmd_options);
  grub_tpm2_protector_clear_cmd =
    grub_register_extcmd ("tpm2_key_protector_clear",
                          grub_tpm2_protector_clear_cmd_handler, 0, NULL,
                          N_("Clear the TPM2 key protector if previously initialized."),
                          NULL);
  grub_key_protector_register (&grub_tpm2_key_protector);
}

GRUB_MOD_FINI (tpm2)
{
  grub_free ((void *) grub_tpm2_protector_ctx.keyfile);
  grub_memset (&grub_tpm2_protector_ctx, 0, sizeof (grub_tpm2_protector_ctx));

  grub_key_protector_unregister (&grub_tpm2_key_protector);
  grub_unregister_extcmd (grub_tpm2_protector_clear_cmd);
  grub_unregister_extcmd (grub_tpm2_protector_init_cmd);
}
