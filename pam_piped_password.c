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

/* PAM entry point for authentication verification */
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

  // expect single simple command
  if (argc != 1) { return(PAM_IGNORE); }

  int pgu_ret;

  // get user
  const char *user = NULL;
  pgu_ret = pam_get_user(pamh, &user, NULL);
  if (pgu_ret != PAM_SUCCESS || user == NULL) { return(PAM_IGNORE); }

  // set PAM_USER in the enviroment
  char *key = "PAM_USER=";
  int userl = strlen(key) + strlen(user) + 1;
  char pam_user[userl];
  strcpy(pam_user, key);
  strcat(pam_user, user);
  pgu_ret = pam_putenv(pamh, pam_user);
  if (pgu_ret != PAM_SUCCESS) { return(PAM_IGNORE); }

  // get the password via the simple command
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
          pgu_ret = pam_set_item(pamh, PAM_AUTHTOK, pwd);
          if (pgu_ret == PAM_SUCCESS) {
            // everything as expected, go!
            return(PAM_SUCCESS);
          }
        }
      }
    }else{
      pclose(pipe);
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
