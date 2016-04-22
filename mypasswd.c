/**
 *	Filippo Callegari - april 2016
 *	This suorce is under GNU v3 license.
 *
 *	Compile this code with this command:
 *	gcc name_of_source.c -lcrypt -o name_of_executable $(mysql_config --libs --cflags)
 *
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <crypt.h>
#include <mysql.h>
#include <stdbool.h>
#include <time.h>

#define PASSWD_LENGTH 34
#define PASSWD_MY_LEGTH 60
#define USER_MY_LENGTH 50
#define MAX_QUERY_LEN 256

#define __CIPHER "$1$"
#define __SALT_len	8

#define __DBUSER "DB_USER_U_SHOULD_KNOW_IT"
#define __DBPASS "I_DON'T_KNOW_UR_DB_PASS_SER"
#define __HOST "localhost"
#define __DBNAME "WHERE_IS_STORED_PASSWORD"
#define __SOCK "/run/mysqld/mysqld.sock"

#define __SELECT_QUERY "SELECT password FROM users WHERE username= \"%s\" AND uid= %d"
#define __UPDATE_QUERY "UPDATE users SET password= \"%s\" WHERE username= \"%s\" AND uid= %d"


bool getUserInfo(char **cuser, int *cuid);
bool getConnectMysql(MYSQL **sock);
bool do_MySQL_SELECT_PASSWORD(MYSQL *sock, char **password, char *user, int cuid);
bool do_MySQL_UPDATE_PASSWORD(MYSQL *sock, char **passwdhash, char* user, int cuid);
char* make_rand_salt(size_t len);
char* make_hashed_pass(char *new_password);
bool chk_passwd(char *password, char *password2check);
bool chk_new_passwd(char *old_passwd);

int main(int argc, char **argv)
{
	/* attrib
	 * char:
	 *  - *cuser: current_username
	 *  - *passwd: selected password
	 *  - tmpstr1: tmp string 1
	 *
	 * int:
	 *  - ciud: current user id
	 *
	 * MYSQL:
	 *  - conn: connection to db;
	 */

	char *cuser, *passwd;
	char tmpstr1[MAX_QUERY_LEN];
	int cuid=0;
	MYSQL *conn=NULL;

	if(!getUserInfo(&cuser,&cuid)){								//getUID
		printf("Error while getting user information. Exit\n");
		exit(EXIT_FAILURE);}

	if(!getConnectMysql(&conn)){								//mysqlconn
                printf("Error while getting MySQL connection.\n%s.\nExit\n",mysql_error(conn));
                exit(EXIT_FAILURE);}

	if(!do_MySQL_SELECT_PASSWORD(conn, &passwd, cuser, cuid)){
			printf("Error while SELECT from MySQL.\nERROR:%s",passwd);
			exit(EXIT_FAILURE);}

	//check password
	printf("Changing password for %s.\n",cuser);
	strcpy(tmpstr1,getpass("(current) UNIX password:"));

	if(strlen(tmpstr1)==0 || !chk_passwd(passwd,tmpstr1) || !chk_new_passwd(tmpstr1)){
		printf("passwd: Authentication token manipulation error\npasswd: password unchanged\n");
		exit(EXIT_FAILURE);
	}

	//create new hashed password
	passwd=make_hashed_pass(tmpstr1);

	//reset connnection
	mysql_close(conn);
	if(!getConnectMysql(&conn)){								//mysqlconn
	                printf("Error while getting MySQL connection.\n%s.\nExit\n",mysql_error(conn));
	                exit(EXIT_FAILURE);}

	//update
	if(!do_MySQL_UPDATE_PASSWORD(conn, &passwd, cuser, cuid)){
		printf("Error while UPDATE PASSWORD for MySQL.\nERROR:%s",passwd);
		exit(EXIT_FAILURE);
	}

	mysql_close(conn);

	printf("passwd: password updated successfully\n");

	exit(EXIT_SUCCESS);
}

/**
 *	Get *Unix info.
 *	@param Pointer to username
 *	@param Pointer to UID
 */
bool getUserInfo(char **cuser, int *cuid)
{
	register struct passwd *user=getpwuid(geteuid());

	*cuser=user->pw_name;
	*cuid=(int)user->pw_uid;

	return (cuser && *cuid);
}

/**
 *	Get init the MySQL Connection.
 *	@param Pointer to main Variable
 */
bool getConnectMysql(MYSQL **sock)
{
	*sock=mysql_init(NULL);
	return mysql_real_connect(*sock, __HOST, __DBUSER, __DBPASS, __DBNAME, 0, __SOCK, 0);
}

/**
 * Get from MySQL the user's password
 * Error in passwdhash String
 *
 * @param Pointer to the MySQL's socket
 * @param Pointer to the hashed password
 * @param Current username
 * @param Current uid
 */
bool do_MySQL_SELECT_PASSWORD(MYSQL *sock, char **password, char *user, int cuid)
{
	//MYSQL_RES *result;
	MYSQL_ROW row;
	char query[MAX_QUERY_LEN];

	sprintf(query,__SELECT_QUERY,user,cuid);

	if(mysql_query(sock,query)){
		*password=strcat("MALFORMED SELECT QUERY. ABORT.\n",mysql_error(sock));
		return false;}

	MYSQL_RES *result=mysql_use_result(sock);
	row=mysql_fetch_row(result);

	*password=row[0];

	//ci sarebbe da fare la free, ma non la mettiamo causa perdita corrispondenza memoria
	return true;


}

/**
 * Update the user password explicited in param **passwdhash.
 * Error in passwdhash String
 *
 * @param Pointer to the MySQL's socket
 * @param Pointer to the hashed password
 * @param Current username
 * @param Current uid
 */
bool do_MySQL_UPDATE_PASSWORD(MYSQL *sock, char **passwdhash, char *user, int cuid)
{
	char query[MAX_QUERY_LEN];

	sprintf(query,__UPDATE_QUERY,*passwdhash,user,cuid);

	if(mysql_query(sock,query)){
			*passwdhash=strcat("MALFORMED UPDATE QUERY. ABORT.\n",mysql_error(sock));
			return false;}

	return true;
}


/**
 * Check if the hashed password corrispond to the hash of the password
 *
 * @param Hashed password
 * @param Password to check.
 */
bool chk_passwd(char *password, char *password2check)
{
	return (strcmp(password,crypt(password2check,password))==0)?true:false;
}


/**
 * Get the new password, and check if it's null || is equal to precedent.
 *
 * @param string contain old password
 */
bool chk_new_passwd(char *old_passwd)
{
	char tmp1[MAX_QUERY_LEN], tmp2[MAX_QUERY_LEN];
	int i;
	for(i=0; i<3; i++){
		strcpy(tmp1,getpass("Enter new UNIX password:"));
		strcpy(tmp2,getpass("Retype new UNIX password:"));

		if(strcmp(tmp1,tmp2)!=0){
			printf("Sorry, passwords do not match\n");
			return false;
		}else{
			if(!strlen(tmp1)|| !strlen(tmp2)){
				printf("No password supplied\n");
			}else{
				if(strcmp(tmp1,old_passwd)==0){
					printf("Password unchanged\n");
				}else{
					strcpy(old_passwd,tmp1);
					return true;
				}
			}
		}
	}
	return false;
}


/**
 * Make a randomize salt long param char
 *
 * @param How long would you like the salt?
 */
char* make_rand_salt(size_t len)
{
	char *salt=(char*)malloc(sizeof(char)*((int)len));
	char *charset="0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?@[\\]^_`{|}";
	int size=strlen(charset);

	srand(time(NULL));

	for(int i=0; i<len; i++)
		salt[i]=charset[rand()%size];

	return salt;
}


/**
 *	Generate an hashed password (md5,...) depends
 *
 *	@param password to encode
 */
char* make_hashed_pass(char *new_password)
{
	char easysalt[PASSWD_LENGTH];
	sprintf(easysalt,"%s%s",__CIPHER,make_rand_salt(__SALT_len));

	return crypt(new_password,easysalt);
}

