#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>

void log_evento(const char* mensaje, const char* nivel);

#define TARGET_IP "127.0.0.1"
#define TIMEOUT_SEC 1
#define MAX_PORTS 65535
#define  LOG_LIFE "port_scan.log"
#define LOG_FILE "/var/log/guardian_puertos.log"
#define RESULT_FILE "/tmp/puertos_abiertos.dat"  // Archivo compartido

volatile __sig_atomic_t running = 1;
volatile __sig_atomic_t report_pending = 0; //controlar que estan solicitando el reporte

typedef enum {
    ANOMALY_NONE = 0,
    ANOMALY_UNKNOWN_PORT,
    ANOMALY_NOT_WHITELISTED,
    ANOMALY_BACKDOOR,
    ANOMALY_MALWARE_PORT,
    ANOMALY_METASPLOIT_DEFAULT,
} AnomalyType;

const char *anomaly_descriptions[] = {
    "Sin anomalias",
    "Puerto no registrado",
    "No en whitelist",
    "Posible Backdoor",
    "Puerto de malware",
    "Metasploit default"
};

typedef struct{
    int port;
    const char *service;
    const char *description;
    int anomaly;
} PortInfo;

PortInfo common_services[] = {
    {20, "FTP-DATA", "Transferencia de archivos",0},
    {21, "FTP", "Control FTP",0},
    {22, "SSH", "Acceso seguro",0},
    {23, "Telnet", "Acceso remoto inseguro",0},
    {25, "SMTP", "Correo saliente",0},
    {53, "DNS", "Resolucion de nombres",0},
    {80, "HTTP", "Trafico web",0},
    {443, "HTTPS", "Web segura",0},
    {3306, "MySQL", "Base de Datos",0},
    {3389, "RDP", "Escritorio remoto",0},
    {8080, "HTTP-ALT", "Servidor web alternativo", 0},

    //--PUERTOS DE MALWARE (PARA DETECCION)--
    {666, "DOOM", "Malware/Backdoor", 0},
    {3666, "DarkComet?/RAT", "Posible RAT (Remote Access Trojan)", 0},
    {4444, "Metasploit", "Listener predeterminado de Metasploit", 0},
    {31337, "Backdoor", "Puerta de backdoor comun", 0},
    {0,NULL,NULL,0}
};
int allowed_ports[]={22,80,443,0};
typedef struct{
    int port;
    const char *service;
    const char *description;
    AnomalyType anomalies[3];
    int anomaly_count;
}ScanResult;

ScanResult *results = NULL;
int total_open =0;
int total_anomalies = 0;

void guardar_resultados() {
    int fd = open(RESULT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), 
                "Error abriendo %s: %s", RESULT_FILE, strerror(errno));
        perror(error_msg);
        log_evento(error_msg, "ERROR");
        return;
    }
    
    FILE *f = fdopen(fd, "w");
    if (!f) {
        perror("Error convirtiendo descriptor a FILE*");
        close(fd);
        return;
    }
    
    for(int i = 0; i < total_open; i++) {
        fprintf(f, "%d|%s|%s|", 
                results[i].port,
                results[i].service,
                results[i].description);
                
        for(int j = 0; j < results[i].anomaly_count; j++) {
            fprintf(f, "%d", results[i].anomalies[j]);
            if(j < results[i].anomaly_count - 1) fprintf(f, ",");
        }
        fprintf(f, "\n");
    }
    
    fclose(f); 
    printf("Resultados guardados exitosamente en %s\n", RESULT_FILE);
}

const char* get_service_name(int port)
{
    for(int i=0; common_services[i].service != NULL;i++)
    {
        if(common_services[i].port == port)
        {
            return common_services[i].service;
        }
    }
    return "Desconocido";
}
const char* get_service_description(int port)
{
    for(int i=0; common_services[i].service != NULL;i++)
    {
        if(common_services[i].port == port)
        {
            return common_services[i].description;
        }
    }
    return "Servicio no registrado";
}
int is_port_allowed(int port){
    for(int i=0;allowed_ports[i] != 0; i++)
    {
        if(allowed_ports[i] == port){
            return 1;
        }
    }
    return 0;
}

void check_anomalies(int port, ScanResult *result)
{
    const char *service = get_service_name(port);

    if(strcmp(service, "Desconocido") == 0){
        result -> anomalies[result ->anomaly_count++] = ANOMALY_UNKNOWN_PORT;
        total_anomalies++;
    }
    else if(!is_port_allowed(port))
    {
        result-> anomalies[result->anomaly_count++]= ANOMALY_NOT_WHITELISTED;
        total_anomalies++;
    }
    switch (port)
    {
    case 31337:
        result->anomalies[result->anomaly_count++]= ANOMALY_BACKDOOR;
        total_anomalies++;
        break;
    case 3666:
        result->anomalies[result->anomaly_count++]= ANOMALY_MALWARE_PORT;
        total_anomalies++;
        break;    
    case 4444:
        result->anomalies[result->anomaly_count++]= ANOMALY_METASPLOIT_DEFAULT;
        total_anomalies++;
        break;
    case 666:
        result -> anomalies[result->anomaly_count++] = ANOMALY_MALWARE_PORT;
        break;
    }
}

void parse_ports(char* input, int* start, int* end){
    char* token =  strtok(input, "-");
    if(token == NULL){
        fprintf(stderr, "Formato invalido. Use inicio-fin\n");
        exit(EXIT_FAILURE);
    }
    *start = atoi(token);
    token = strtok(NULL, "-");
    *end = (token != NULL) ? atoi(token) : *start;

    if(*start < 1 || *end > MAX_PORTS || *start > *end){
        fprintf(stderr, "Rango invalido (1 - 65535)\n");
        exit(EXIT_FAILURE);
    }
} 
int scan_port(int port)
{
    struct  sockaddr_in sa;
    int sock = socket(AF_INET, SOCK_STREAM,0);
    if(sock < 0)
    {
        perror("Error en socket()");
        return -1;
    }

    //Configurar timeout
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET,SO_SNDTIMEO, &tv, sizeof(tv));

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET,TARGET_IP,&sa.sin_addr);

    int result = connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    close(sock);
    
    return (result == 0) ? 1 : 0;
    
}

void handle_signal(int sig) {
    if(sig == SIGINT) {
        if (report_pending) {
            log_evento("Segunda señal SIGINT recibida. Deteniendo programa", "WARN");
            running = 0;
        } else {
            log_evento("SIGINT recibida. Generando reporte pendiente", "INFO");
            report_pending = 1;
        }
    }
}

void setup_signal_handler()
{
    struct sigaction sa;
    
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,&sa, NULL);   
}

// Función para escribir en el log
void escribir_log(const char* mensaje, const char* nivel) {
    FILE *log_file = fopen(LOG_FILE, "a"); // Modo append
    if (!log_file) {
        perror("Error abriendo archivo de log");
        return;
    }

    // Obtener fecha/hora actual
    time_t ahora = time(NULL);
    struct tm *t = localtime(&ahora);
    char fecha_hora[20];
    strftime(fecha_hora, sizeof(fecha_hora), "%Y-%m-%d %H:%M:%S", t);

    // Escribir en el log: [fecha] [nivel] mensaje
    fprintf(log_file, "[%s] [%s] %s\n", fecha_hora, nivel, mensaje);
    fclose(log_file);
}

// Función para registrar eventos con diferentes niveles
void log_evento(const char* mensaje, const char* nivel) {
    // Escribir en consola
    if (strcmp(nivel, "ERROR") == 0) {
        printf("\033[1;31m[%s] %s\033[0m\n", nivel, mensaje);
    } else if (strcmp(nivel, "INFO") == 0) {
        printf("\033[1;32m[%s] %s\033[0m\n", nivel, mensaje);
    } else if (strcmp(nivel, "WARN") == 0) {
        printf("\033[1;33m[%s] %s\033[0m\n", nivel, mensaje);
    } else {
        printf("[%s] %s\n", nivel, mensaje);
    }
    
    // Escribir en archivo de log
    escribir_log(mensaje, nivel);
}
void print_report() {
    printf("\n\n=== REPORTE DE ESCANEO ===\n");
    printf("IP Objetivo: \033[1;34m%s\033[0m\n",TARGET_IP);
    printf("Puertos escaneados: %d\n\n", total_open);

    printf("=== PUERTOS ABIERTOS ===\n");
    for(int i=0; i< total_open; i++)
    {
        printf("\n\033[1;33m%d\033[0m/%s - %s\n",
        results[i].port, results[i].service, results[i].description);
            
        if(results[i].anomaly_count > 0){
            printf("  \033[1;31mAnomalias:\033[0m\n");
            for(int j =0; j< results[i].anomaly_count; j++){
                printf("  ~%s\n", anomaly_descriptions[results[i].anomalies[j]]);
            }
        }
    }

    printf("\n=== RESUMEN ===\n");
    printf("Total puertos abiertos: %d\n", total_open);
    printf("Total anomalias detectadas: \033[1;31m%d\033[0m\n", total_anomalies);
    printf("\n=== FIN DEL REPORTE ===\n");
    // Registrar el reporte completo en el log
    char log_msg[512];
    snprintf(log_msg, sizeof(log_msg), "REPORTE: %d puertos abiertos, %d anomalías", 
             total_open, total_anomalies);
    log_evento(log_msg, "INFO");
}

int main(int argc, char *argv[]) {
    int fd = open(RESULT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd != -1) {
        close(fd);
        printf("Archivo de resultados inicializado\n");
    } else {
        perror("Error creando archivo inicial");
    }
    // FILE *log = fopen(LOG_FILE, "a");
    // if (log) fclose(log);
    // else perror("Error creando archivo de log");
    setup_signal_handler();
    
    int start, end;
    if(argc != 2){
        printf("Uso: %s <rango-puertos>\nEj: %s 1-1000\n", argv[0],argv[0]);
        return EXIT_FAILURE;
    }
    parse_ports(argv[1],&start,&end);

    // Iniciar log
    log_evento("Iniciando escaneo continuo", "INFO");
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Rango de puertos: %d-%d", start, end);
    log_evento(log_msg, "INFO");

    int max_ports = end - start + 1;
    printf("\033[1;36m[+] Escaneo continuo en %s (%d - %d)\033[0m\n", TARGET_IP, start, end);
    results = malloc(max_ports * sizeof(ScanResult));
    
    if(!results) {
        log_evento("Error asignando memoria para resultados", "ERROR");
        return EXIT_FAILURE;
    }

    while (running) {
        printf("/////EMPEZANDO ESCANEO/////\n");
        total_anomalies = 0;
        total_open = 0;
        
        // Inicialización segura de resultados
        for(int i = 0; i < max_ports; i++) {
            results[i].port = 0;
            results[i].service = NULL;
            results[i].description = NULL;
            results[i].anomaly_count = 0;
            for(int j = 0; j < 3; j++) {
                results[i].anomalies[j] = ANOMALY_NONE;
            }
        }
        
        for(int port = start; port <= end && running; port++) {
            if(scan_port(port)) {
               
                if(total_open >= max_ports) {
                    log_evento("Demasiados puertos abiertos, aumentando capacidad", "WARN");
                    break;
                }
                
                const char *service = get_service_name(port);
                const char *description = get_service_description(port);
                
                results[total_open].port = port;
                results[total_open].service = service;
                results[total_open].description = description;
                results[total_open].anomaly_count = 0;
    
                check_anomalies(port, &results[total_open]);
                
                printf("\033[1;32m[+] Puerto %d/%s - %s\033[0m\n", port, service, description);
                
                char port_msg[128];
                snprintf(port_msg, sizeof(port_msg), "Puerto %d/%s abierto: %s", 
                         port, service, description);
                log_evento(port_msg, "INFO");
                
                if (results[total_open].anomaly_count > 0) {
                    for(int j = 0; j < results[total_open].anomaly_count; j++) {
                        char anomaly_msg[128];
                        snprintf(anomaly_msg, sizeof(anomaly_msg), 
                                 "ANOMALÍA en puerto %d: %s", 
                                 port, anomaly_descriptions[results[total_open].anomalies[j]]);
                        log_evento(anomaly_msg, "WARN");
                    }
                }
                total_open++;
            }
        }
        
        guardar_resultados();
        
        if(report_pending) {
            print_report();
            report_pending = 0;
        }
        
        log_evento("Ciclo de escaneo completado", "DEBUG");
        sleep(10);
    }
    
    print_report();
    free(results);
    log_evento("Escaneo detenido", "INFO");
    return EXIT_SUCCESS;
}