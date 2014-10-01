/* Define which PAM interfaces we provide */
#define PAM_SM_ACCOUNT
#define PAM_SM_AUTH
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION

#include <unistd.h>
#include <stdio.h>
#include <string.h>

/* Include PAM headers */
#include <security/pam_appl.h>
#include <security/pam_modules.h>

/* PAM entry point for session creation */
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}

/* PAM entry point for session cleanup */
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}

/* PAM entry point for accounting */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}

/*
 * PAM entry point for authentication verification
 * Note:  I don't know what I should return if unable to clear ENV
 * or why that would ever happen, so just returning PAM_IGNORE.
 */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

  // Expect a single simple command.
  if (argc != 1) { return(PAM_IGNORE); }

  int ret;

  // Get user.
  const char *USER = NULL;
  ret = pam_get_user(pamh, &USER, NULL);
  if (ret != PAM_SUCCESS || USER == NULL) { return(PAM_IGNORE); }

  // PAM_USER PAM_USER= PAM_USER=username
  const char *KEY = "PAM_USER";

  // Set PAM_USER in the enviroment to username.
  int userl = strlen(KEY) + strlen(USER) + 2;
  char pam_user[userl];
  strcpy(pam_user, KEY);
  strcat(pam_user, "=");
  strcat(pam_user, USER);
  ret = pam_putenv(pamh, pam_user);
  if (ret != PAM_SUCCESS) { return(PAM_IGNORE); }

  // Get the password via the simple command.
  int got_pwd = 0;
  int pwdl = 65;
  char pwd[pwdl];
  FILE *pipe;
  pipe = popen(argv[0], "r");
  if (pipe != NULL) {
    if (fgets(pwd, pwdl, pipe)){
      if (pclose(pipe)==0) {
        int n = strlen(pwd)-1;
        if (pwd[n] == '\n'){
          pwd[n] = '\0'; // End Of String
          got_pwd = 1;
        }
      }
    }else{
      pclose(pipe);
    }
  }

  // Clear PAM_USER from enviroment.
  ret = pam_putenv(pamh, KEY);
  if (ret != PAM_SUCCESS) { return(PAM_IGNORE); }

  // Set PAM_AUTHTOK with pwd.
  if (got_pwd==1) {
    ret = pam_set_item(pamh, PAM_AUTHTOK, pwd);
    if (ret == PAM_SUCCESS) {
      // Was able to set password, everything as expected, go!
      return(PAM_SUCCESS);
    }
  }

  return(PAM_IGNORE);
}

/*
*      PAM entry point for setting user credentials (that is, to actually
*           establish the authenticated user's credentials to the service provider)
*              */
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}

/* PAM entry point for authentication token (password) changes */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return(PAM_IGNORE);
}
