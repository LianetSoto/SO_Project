#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#define CONFIG_PATH "/etc/matcomguard.conf"
#define DEFAULT_CPU_THRESHOLD 5
#define DEFAULT_RAM_THRESHOLD 5
#define DEFAULT_DURATION 2

typedef struct {
    pid_t pid;                  //ID del proceso
    char name[256];             //nombre del ejecutabke
    unsigned long cpu_usage;    //tiempo total de cpu consumido
    unsigned long ram_usage;    //memoria ram utilizada
    time_t start_time;          //primer momento en el que el proceso supero los umbrales 
    time_t last_alert;          //momento de ultima alerta generada
    double cpu_percent;         //porcentaje actual de uso de CPU
    double ram_percent;         //porcentaje actual de uso de RAM
} Proceso;

typedef struct {
    int cpu_threshold;          //umbral maximo de CPU
    int ram_threshold;          //umbral maximo de RAM
    int alert_duration;         //duracion minima para alerta
    char whitelist[10][256];    //lista de procesos permitidos
    int whitelist_count;        //numero de procesos en la lista blanca
} Configuracion;

void leer_configuracion(Configuracion *config) {
    config->cpu_threshold = DEFAULT_CPU_THRESHOLD;
    config->ram_threshold = DEFAULT_RAM_THRESHOLD;
    config->alert_duration = DEFAULT_DURATION;
    config->whitelist_count = 0;

    FILE *archivo = fopen(CONFIG_PATH, "r");
    if (!archivo) return;

    char linea[256];
    while (fgets(linea, sizeof(linea), archivo)) {
        if (strstr(linea, "UMBRAL_CPU")) 
            sscanf(linea, "UMBRAL_CPU=%d", &config->cpu_threshold);
        else if (strstr(linea, "UMBRAL_RAM"))
            sscanf(linea, "UMBRAL_RAM=%d", &config->ram_threshold);
        else if (strstr(linea, "WHITELIST"))
            sscanf(linea, "WHITELIST=%255s", config->whitelist[config->whitelist_count++]);
    }
    fclose(archivo);
}

void obtener_tiempos_cpu(pid_t pid, unsigned long *utime, unsigned long *stime) //lee /proc/<PID>/stat para obtener tiempos de CPU
{
    char path[256], buffer[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    
    if (f && fgets(buffer, sizeof(buffer), f)) {
        char *token = strtok(buffer, " "); 
        for (int i = 1; i <= 13; i++) token = strtok(NULL, " "); 
        
        *utime = strtoul(token, NULL, 10);        
        token = strtok(NULL, " ");
        *stime = strtoul(token, NULL, 10);        
    }
    fclose(f);
}

double calcular_porcentaje_cpu(Proceso *actual, Proceso *anterior, double intervalo) //calcula el % de cpu usado (actual - anterior)
{
    unsigned long delta_total = (actual->cpu_usage - anterior->cpu_usage);
    return (delta_total * 100.0) / (sysconf(_SC_CLK_TCK) * intervalo);
}

double calcular_porcentaje_ram(unsigned long vm_rss) //lee /proc/meminfo para obtener ram total
{
    static unsigned long ram_total = 0;
    if (ram_total == 0) { 
        FILE *f = fopen("/proc/meminfo", "r");
        if (f) {
            fscanf(f, "MemTotal: %lu kB", &ram_total);
            fclose(f);
        }
    }
    return (ram_total > 0) ? (vm_rss * 100.0) / ram_total : 0; //calcula el % de ram usado
}

void calcular_uso_recursos(Proceso *p) //para actualizar los datos de un proceso
{
    unsigned long utime, stime;
    obtener_tiempos_cpu(p->pid, &utime, &stime);
    p->cpu_usage = utime + stime;
    
    char path[256], buffer[256];
    snprintf(path, sizeof(path), "/proc/%d/status", p->pid);
    FILE *f = fopen(path, "r");
    if (f) {
        while (fgets(buffer, sizeof(buffer), f)) {
            if (strncmp(buffer, "VmRSS:", 6) == 0) {
                sscanf(buffer + 6, "%lu kB", &p->ram_usage);
                break;
            }
        }
        fclose(f);
    }
    
    p->ram_percent = calcular_porcentaje_ram(p->ram_usage);
}

int es_proceso_traidor(Proceso *p, Configuracion *config) 
{
    for(int i = 0; i < config->whitelist_count; i++) //ignorar los procesos de la lista blanca
    {
        if(strcmp(p->name, config->whitelist[i]) == 0) return 0;
    }
    
    //si los procesos superan el umbral de cpu o ram
    if((p->cpu_percent > config->cpu_threshold) || (p->ram_percent > config->ram_threshold)) 
    {
        time_t ahora = time(NULL);
        if(p->start_time == 0) //registra la primera vez que lo detecta
        {
            p->start_time = ahora;
            return 0;
        }
        //verifica si excede la duracion configurada
        return  (difftime(ahora, p->start_time) >= config->alert_duration);
    }
    p->start_time = 0;
    return 0;
}

int es_pid_valido(const char *nombre) 
{
    //verificar si todos los caracteres son digitos
    for (int i = 0; nombre[i] != '\0'; i++) {
        if (!isdigit(nombre[i])) {
            return 0;
        }
    }

    //verifica que exista el directorio del proceso en /proc
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/stat", nombre);
    
    return (access(path, F_OK) == 0);
}

void obtener_nombre_proceso(char *nombre, pid_t pid) {
    char path[256];
    FILE *fp;
    char buffer[256];
    
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    
    fp = fopen(path, "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strncmp(buffer, "Name:", 5) == 0) {
                char *start = buffer + 6; 
                while (*start == ' ' || *start == '\t') start++;
                char *end = strchr(start, '\n');
                if (end) *end = '\0';
                strncpy(nombre, start, 255);
                break;
            }
        }
        fclose(fp);
    } else {
        strcpy(nombre, "desconocido");
    }
}

int obtener_procesos_actuales(Proceso *procesos, Configuracion *config) 
{
    DIR *dir = opendir("/proc"); //listar PIDS activos
    struct dirent *entrada;
    int count = 0;
    
    while((entrada = readdir(dir)) && count < 500) {
        if(es_pid_valido(entrada->d_name)) //verificar si un directorio en /proc corresponde a un pid valido
        {
            procesos[count].pid = atoi(entrada->d_name);
            obtener_nombre_proceso(procesos[count].name, procesos[count].pid);
            
        if(strstr(procesos[count].name, "stress-ng") != NULL) {
        	printf("[DEBUG} Proceso detectado: %s (PID: %d)\n", procesos[count].name, procesos[count].pid);
        }
            count++;
        }
    }
    closedir(dir);
    return count;
}

void registrar_alerta(Proceso *p, Configuracion *config) 
{
    time_t ahora = time(NULL);
    struct tm *tiempo = localtime(&ahora);
    char timestamp[20];
    char log_entry[512];
    
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", tiempo);
    
    //genera el mensaje con los detalles
    snprintf(log_entry, sizeof(log_entry),
        "[%s] ALERTA: %s (PID: %d)\n"
        "-> CPU: %.2f%% (Umbral: %d%%)\n"
        "-> RAM: %.2f%% (Umbral: %d%%)\n"
        "-> Duración: %ld segundos\n\n",
        timestamp,
        p->name,
        p->pid,
        p->cpu_percent,
        config->cpu_threshold,
        p->ram_percent,
        config->ram_threshold,
        time(NULL) - p->start_time
    );

    //VISTA ALERTA ejemplo
    /*
    [A-M-D Hora] ALERTA: stress-ng (PID: 12345)
    -> CPU: 85.00% (Umbral: 5%)
    -> RAM: 15.00% (Umbral: 5%)
    -> Duración: 5 segundos
    */
    
    printf("\033[1;31m"); 
    printf("%s", log_entry);
    printf("\033[0m"); 

    //guardarlo en el registro
    FILE *log = fopen("/var/log/guardian_procesos.log", "a");
    if (log) {
        fprintf(log, "%s", log_entry);
        fclose(log);
    }
}

void verificar_umbrales(Proceso *actual, Proceso *previos, int num_previos, Configuracion *config, double intervalo) 
{   
    //compara procesos actuales con procesos previos
    for(int i = 0; i < num_previos; i++) {
        if(previos[i].pid == actual->pid) {
            actual->cpu_percent = calcular_porcentaje_cpu(actual, &previos[i], intervalo);
        
            if(actual->cpu_percent > config->cpu_threshold || actual->ram_percent > config->ram_threshold) 
            {
                if(actual->start_time == 0) actual->start_time = time(NULL);
            } 
            else 
            {   
                actual->start_time = 0;
            }
            
            if(es_proceso_traidor(actual, config)) //para registrar la alerta si es traidor
            {
                registrar_alerta(actual, config);
            }
            break;
        }
    }
}

void vigilancia_real(time_t intervalo, Configuracion *config) 
{
    //reserva memoria para 500 procesos (actuales y previos)
    Proceso *procesos_previos = calloc(500, sizeof(Proceso));
    Proceso *procesos_actuales = calloc(500, sizeof(Proceso));
    int num_procesos = 0;
    time_t tiempo_previo = time(NULL);
    
    if(!procesos_previos || !procesos_actuales) 
    {
    	perror("Error asignando memoria");
    	exit(EXIT_FAILURE);
    }
    
    //obtener procesos iniciales y recursos
    num_procesos = obtener_procesos_actuales(procesos_previos, config);
    for(int i = 0; i < num_procesos; i++)
    {
    	calcular_uso_recursos(&procesos_previos[i]);
    }

    while(1) 
    {
        time_t tiempo_actual = time(NULL);
        double delta_tiempo = difftime(tiempo_actual, tiempo_previo);
        
        //obtener procesos actuales y comprar con procesos previos
        int num_actual = obtener_procesos_actuales(procesos_actuales, config);
        
        for(int i = 0; i < num_actual; i++) 
        {
            calcular_uso_recursos(&procesos_actuales[i]);
            
            for(int j =0; j < num_procesos; j++)
            {
            	if(procesos_actuales[i].pid == procesos_previos[j].pid)
                {
            		double intervalo_real = difftime(tiempo_actual, tiempo_previo);
            		procesos_actuales[i].cpu_percent = calcular_porcentaje_cpu(&procesos_actuales[i], &procesos_previos[j], intervalo_real);
            		break;
            	}
            }
            verificar_umbrales(&procesos_actuales[i], procesos_previos, num_procesos, config, delta_tiempo);
        }
        
        memcpy(procesos_previos, procesos_actuales, sizeof(Proceso) * num_actual);
        num_procesos = num_actual;
        tiempo_previo = tiempo_actual;
        
        printf("---Ciclo completado ---\n");
        //for(int i =0; i< num_actual; i++){
        //	printf("PID: %d, Nombre: %s, CPU: %.2f%%, RAM: %.2f%%\n", procesos_actuales[i].pid, procesos_actuales[i].name, procesos_actuales[i].cpu_percent, procesos_actuales[i].ram_percent);
        //}
        
        sleep(intervalo);
    }
    free(procesos_previos);
    free(procesos_actuales);
}

int main(int argc, char *argv[]) 
{
    //crear el registro log
    FILE *log_procesos = fopen("/var/log/guardian_procesos.log", "a");
    if (log_procesos) fclose(log_procesos);
    else perror("No se pudo crear /var/log/guardian_procesos.log");
    Configuracion config;
    leer_configuracion(&config);
    
    time_t intervalo = 1; 
    
    if(argc > 1) {
        for(int i = 1; i < argc; i++) {
            if(strcmp(argv[i], "-i") == 0 && i+1 < argc) intervalo = atoi(argv[++i]);
        }
    }
    
    vigilancia_real(intervalo, &config);
    
    return 0;
}
