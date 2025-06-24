#include <stdio.h>      // Para printf, FILE, etc.
#include <stdlib.h>     // Para malloc, free, size_t, exit, etc.
#include <string.h>     // Para strcpy, memcpy, strlen, etc.
#include <sys/types.h>  // Para uid_t, gid_t, mode_t, size_t
#include <sys/stat.h>   // Para struct stat, permisos, etc.
#include <unistd.h>     // Para funciones POSIX (acceso a archivos, etc.)
#include <time.h>       // Para time_t
#include <openssl/sha.h> // Para SHA256_DIGEST_LENGTH y funciones SHA-256
#include <dirent.h>
#include <openssl/evp.h>
#include <signal.h>
#include <libgen.h>

#define IntervaloEscaneo 20
#define Cant_Max_Disp 5
#define MAX_PATH 4096
#define ANOMALIAS_FILE "/tmp/anomalias_dispositivos.dat"

// Estructuras:
typedef struct baseline_info {
    char *ruta;          
    size_t tamanno; // En bytes  
    time_t mtime; // Última modificación (timestamp)
    mode_t permisos; 
    uid_t uid; // Propietario (user ID)
    gid_t gid; // Grupo (group ID)
    char hash[SHA256_DIGEST_LENGTH]; // Hash SHA-256

    char nombre[256];     // nombre del archivo 
    char extension[16];   // extensión del archivo 

}baseline_info;

typedef struct Node
{
    baseline_info info;
    struct Node* next;
} Node;

typedef struct {
    char mount_point[MAX_PATH]; 
    char device_name[256]; 
    int is_monitored; 
    Node *baseline; 
} USBDevice;

typedef struct {
    USBDevice dispositivos[Cant_Max_Disp];
    int total_disp;
    int activo;
} GuardSystem;

// Variables globales
static GuardSystem guard;

//Declaracion de Funciones
void init_guard_system();
int is_usb_device(const char *mount_point);
int calculate_hash(const char *filepath, char *hash_output);
Node* Create_Node(const char *ruta, struct stat *st);
void escanear_directorio(const char *path, Node**lista);
void PrintResults(Node *lista);
void LiberarLista(Node *lista);
Node* BuscarArchivo(Node* lista, Node* node, int alert, int *cmp);
void VerificarCrecimientoInusual(const baseline_info* a, const baseline_info* b, int umbral);
int VerificarPermisoCritico(mode_t modo);
void CompararArchivos(const baseline_info* a, const baseline_info* b);
void DetectarCambios(Node* baseline, Node* escaneo_actual);
void scan_mount_points();
void MonitorearDisp(USBDevice *device);
void Exit();
void extraer_nombre_y_extension(const char *ruta, char *nombre, char *extension);
void DispositivosConectados();

void registrar_alerta_dispositivo(const char *tipo, const char *ruta) {
    FILE *f = fopen(ANOMALIAS_FILE, "a");
    if (f) {
        fprintf(f, "%s|%s\n", tipo, ruta);
        fclose(f);
    }
    
    // También imprimir en consola
    printf("\033[1;31m[ALERTA] %s: %s \033[0m\n", tipo, ruta);
}

int main()
{
    signal(SIGINT, Exit);
    signal(SIGTERM, Exit);

    init_guard_system();

    printf("🛡️  MatCom Guard iniciado - Patrullando las fronteras del reino...\n");
    printf("🔄 Intervalo de escaneo: %d segundos\n\n", IntervaloEscaneo);
        
    
    // Ciclo principal de monitoreo
    while (guard.activo) {
        FILE *f = fopen(ANOMALIAS_FILE, "w");
        if (f) fclose(f);
        DispositivosConectados();
        
        // EJECUTAR MONITOREO PARA CADA DISPOSITIVO
        for (int i = 0; i < guard.total_disp; i++) {
            if (guard.dispositivos[i].is_monitored) {
                MonitorearDisp(&guard.dispositivos[i]);  // <-- LLAMADA CLAVE
            }
        }

        FILE *f_dispositivos = fopen("/tmp/dispositivos.dat", "w");
        if (f_dispositivos) {
            for (int i = 0; i < guard.total_disp; i++) {
                fprintf(f_dispositivos, "Dispositivo: %s\nMontado en: %s\nEstado: %s\n\n",
                    guard.dispositivos[i].device_name,
                    guard.dispositivos[i].mount_point,
                    guard.dispositivos[i].is_monitored ? "Monitoreado" : "Desconectado");
            }
            fclose(f_dispositivos);
        }
        
        sleep(IntervaloEscaneo);
    }
    return 0;
}

void MonitorearDisp(USBDevice *device) {
    if (!device) return;
    
    // Verificar si el dispositivo sigue montado
    if (access(device->mount_point, F_OK) != 0) {
        printf("📤 Dispositivo %s desconectado\n", device->device_name);
        device->is_monitored = 0;
        return;
    }

    printf("🔍 Patrullando %s...\n", device->mount_point);

    Node* base = device->baseline;
    Node* escaneo_actual = NULL;
    escanear_directorio(device -> mount_point, &escaneo_actual);
    DetectarCambios(base, escaneo_actual);
    LiberarLista(escaneo_actual);
}

//Inicializaciones y escaneo 

void init_guard_system() {
    guard.total_disp = 0;
    guard.activo = 1;
}

void DispositivosConectados()
{
    scan_mount_points();

    printf("Dispositivos Conectados \n");
    for (int i = 0; i < guard.total_disp; i++) {
        printf("%s\n", guard.dispositivos[i].mount_point);
        printf("\n");
    }
}

Node* Create_Node(const char *ruta, struct stat *st) {
    Node *new = malloc(sizeof(Node));
    if (!new) return NULL;

    new->info.ruta = strdup(ruta);
    new->info.tamanno = (size_t)st->st_size;
    new->info.mtime = st->st_mtime;
    new->info.permisos = st->st_mode;
    new->info.uid = st->st_uid;
    new->info.gid = st->st_gid;
    
    if (calculate_hash(ruta, new->info.hash) != 0) {
        memset(new->info.hash, 0, SHA256_DIGEST_LENGTH);
    }

    // Extraer nombre y extensión
    extraer_nombre_y_extension(ruta, new->info.nombre, new->info.extension);

    new->next = NULL;
    return new;
}

void escanear_directorio(const char *path, Node**lista) {
    DIR *dir = opendir(path); //Se abre el directorio especificado por PATH
    if (!dir) return; //Se verifica que sea correcto

    struct dirent *entry;
    char ruta_completa[4096];
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        //Omite las entradas especiales "." (directorio actual) y ".." (directorio padre).
        //Para evitar bucles infinitos y no procesar el mismo directorio repetidamente.
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(ruta_completa, sizeof(ruta_completa), "%s/%s", path, entry->d_name);

        if (lstat(ruta_completa, &st) == -1) continue;
        
        if (S_ISDIR(st.st_mode)) //Es una carpeta
        { 
            escanear_directorio(ruta_completa, lista);
        } else if (S_ISREG(st.st_mode)) //Es un archivo regular
        { 
            Node *new = Create_Node(ruta_completa, &st);
            if (new) {
                new->next = *lista;
                *lista = new;
            }
        }
    }
    closedir(dir);
}

//DETECCION DE ANOMALIAS Y MODIFICACIONES 

// Función principal de detección de cambios
void DetectarCambios(Node* baseline, Node* escaneo_actual) {

    printf("\n=== Reporte de Cambios ===\n");
    int cmp = 1;
    
    // 1. Archivos eliminados (están en baseline pero no en actual)
    // Se recorren todos los archivos de base para revisar que no han sido eliminados
    Node* base = baseline;
    while (base) {
        
        if (!BuscarArchivo(escaneo_actual, base, 1, &cmp)) {
            registrar_alerta_dispositivo("Archivo legitimo eliminado", base->info.ruta);
        }
        base = base->next;
    }

    // 2. Archivos nuevos
    //Se recorren todos los actuales, si no se encuentran en baseline entonces fueron agregados
    Node* act = escaneo_actual;
    while (act) {
        cmp = 1;
        Node* encontrado = BuscarArchivo(baseline, act, 0, &cmp);
        
        if (!encontrado) {
            // Alerta para nuevos ejecutables
            if (strcmp(act->info.extension, "exe") == 0) {
                registrar_alerta_dispositivo("Archivo ejecutable añadido", act->info.ruta);
            }
        } else if(cmp){
            CompararArchivos(&encontrado->info, &act->info); //Verificar modificaciones 
        }
        act = act->next;
    }
}

Node* BuscarArchivo(Node* lista, Node* node, int alert, int *cmp) {
    Node* actual = lista;
    while (actual) {
        if (strcmp(actual->info.ruta, node->info.ruta) == 0){
            return actual;
        }
        if(strcmp(node->info.hash, actual->info.hash) == 0) //Fue renombrado, trasladado, replicado
        {
            //Mismo hash, distinto nombre -> replicacion del archivo
            if(strcmp(actual->info.nombre, node->info.nombre) != 0)
            {
                registrar_alerta_dispositivo("Replicacion sospechosa, se encontro replicado el archivo", actual->info.ruta);
                *cmp = 0;
                
            }
            // Alerta especial para cambios a .exe
            if (strcmp(actual->info.extension, "exe") == 0 && strcmp(node->info.extension, "exe") != 0 && alert) {
                registrar_alerta_dispositivo("Cambio de extensión sospechoso", node->info.ruta);
            }  
            return actual;
        }
        actual = actual->next;
    }
    return NULL;
}


// Función para comparar dos archivos
void CompararArchivos(const baseline_info* a, const baseline_info* b) 
{
    if(a->tamanno != b-> tamanno)
    {
        VerificarCrecimientoInusual(a, b, 50 * 1024 * 1024); //50 mb
    }
    if(a->mtime != b->mtime)
    {
        registrar_alerta_dispositivo("Atributo de tiempo alterado del archivo ", a->ruta);
    }
    if(a->permisos != b->permisos)
    {
        if(VerificarPermisoCritico(b -> permisos))
        {
            registrar_alerta_dispositivo("Permiso cambiado del archivo ", a->ruta);
        }
    }
    if(a->uid != b->uid)
    {
        registrar_alerta_dispositivo("UserID modificado en ", a->ruta);
    }
    if(a->gid != b->gid)
    {
        registrar_alerta_dispositivo("GroupID modificado en", a->ruta);

    }
}

void VerificarCrecimientoInusual(const baseline_info* a, const baseline_info* b, int umbral)
{
    if((a -> tamanno > b ->tamanno) && (a -> tamanno - b ->tamanno > umbral))
    {
        registrar_alerta_dispositivo("Decrecimiento inusual del tamanno del archivo", a->ruta);
        
    }
    else if((a -> tamanno < b ->tamanno) && (b ->tamanno - a ->tamanno > umbral))
    {
        registrar_alerta_dispositivo("Crecimiento inusual del tamanno del archivo", a->ruta);
        
    }
}

int VerificarPermisoCritico(mode_t modo)
{
    mode_t permisos = modo & 0777; // Extraer solo bits de permisos rwx para usuario, grupo y otros
    if (permisos == 0777 || permisos == 0666 || permisos == 0000) return 1;
    return 0; // No es crítico
}

// Escaneo de dispositivos conectados
void scan_mount_points() {
    FILE *mounts = fopen("/proc/mounts", "r");
    if (!mounts) {
        perror("Error al abrir /proc/mounts");
        return;
    }
    
    char line[MAX_PATH];
    while (fgets(line, sizeof(line), mounts)) {
        char device[MAX_PATH], mount_point[MAX_PATH], fs_type[64];
        
        if (sscanf(line, "%s %s %s", device, mount_point, fs_type) == 3) {
            // Verificar si es un dispositivo USB
            if (is_usb_device(mount_point)) {
                
                // Buscar si ya está siendo monitoreado
                int found = 0;
                for (int i = 0; i < guard.total_disp; i++) {
                    if (strcmp(guard.dispositivos[i].mount_point, mount_point) == 0) {
                        found = 1;
                        break;
                    }
                }
                
                // Si es nuevo, agregarlo al sistema
                if (!found && guard.total_disp < Cant_Max_Disp) {
                    USBDevice *new_device = &guard.dispositivos[guard.total_disp];
                    
                    // Inicializar completamente la estructura
                    memset(new_device, 0, sizeof(USBDevice));
                    
                    strncpy(new_device->mount_point, mount_point, sizeof(new_device->mount_point) - 1);
                    strncpy(new_device->device_name, device, sizeof(new_device->device_name) - 1);
                    new_device->is_monitored = 1;
                    
                    printf("🔍 Nuevo dispositivo detectado: %s en %s\n", device, mount_point);
                    
                    // Realizar escaneo inicial 
                    printf("📊 Iniciando escaneo inicial...\n");
                    Node *initialscan = NULL;
                    escanear_directorio(new_device -> mount_point, &initialscan);
                    new_device -> baseline = initialscan;
                    guard.total_disp++;
                }
            }
        }
    }
    fclose(mounts);
}

// Metodos Auxiliares
int is_usb_device(const char *mount_point) {
    if (!mount_point) return 0;
    
    // Verificar si el punto de montaje indica un dispositivo USB
    return (strstr(mount_point, "/media/") != NULL ||
            strstr(mount_point, "/mnt/") != NULL ||
            strstr(mount_point, "/run/media/") != NULL);
}

// Imprimir los resultados
void PrintResults(Node *lista){
Node *actual = lista;
while (actual) {
    printf("Archivo: %s\nNombre: %s\nExtension: %s\ntamanno: %zu\nModificado: %ld\nPermisos: %o\nUID: %d\nGID: %d\nSHA256: %s\n\n",
        actual->info.ruta, actual->info.nombre, actual->info.extension, actual->info.tamanno, actual->info.mtime,
        actual->info.permisos & 0777, actual->info.uid, actual->info.gid, actual->info.hash);
    actual = actual->next;
}
}

void LiberarLista(Node *lista) {
    Node *actual = lista;
    while (actual) {
        Node *siguiente = actual->next;
        free(actual->info.ruta); 
        free(actual);
        actual = siguiente;
    }
}

int calculate_hash(const char *filepath, char *hash_output) {
    if (!filepath || !hash_output) return -1;
    
    FILE *file = fopen(filepath, "rb");
    if (!file) return -1;
    
    // Hash simple basado en tamanno, primera parte y última parte del archivo
    struct stat st;
    if (fstat(fileno(file), &st) != 0) {
        fclose(file);
        return -1;
    }
    
    unsigned long hash = st.st_size;
    unsigned char buffer[1024];
    size_t bytes_read;
    
    // Leer primeros 512 bytes
    bytes_read = fread(buffer, 1, 512, file);
    for (size_t i = 0; i < bytes_read; i++) {
        hash = hash * 31 + buffer[i];
    }
    
    // Si el archivo es grande, leer últimos 512 bytes
    if (st.st_size > 1024) {
        if (fseek(file, -512, SEEK_END) == 0) {
            bytes_read = fread(buffer, 1, 512, file);
            for (size_t i = 0; i < bytes_read; i++) {
                hash = hash * 31 + buffer[i];
            }
        }
    }
    
    // Convertir a string hexadecimal
    snprintf(hash_output, SHA256_DIGEST_LENGTH, "%08lx", hash);
    
    fclose(file);
    return 0;
}

void extraer_nombre_y_extension(const char *ruta, char *nombre, char *extension) {
    char *copia = strdup(ruta);

    // Extraer solo el nombre del archivo
    char *nombre_archivo = basename(copia);  // Usa basename para obtener solo el nombre del archivo
    
    // Copiar el nombre completo
    strncpy(nombre, nombre_archivo, 255);
    nombre[255] = '\0';  // Asegurar terminación nula
    
    // Buscar el último punto para la extensión
    char *punto = strrchr(nombre_archivo, '.');
    if (punto && punto != nombre_archivo) {  // Si hay punto y no es un archivo oculto
        strncpy(extension, punto + 1, 15);  // Copiar sin el punto
        extension[15] = '\0';
        
        // Eliminar la extensión del nombre
        *punto = '\0';  // Trunca el nombre en el punto
        strncpy(nombre, nombre_archivo, 255);  // Vuelve a copiar sin extensión
    } else {
        strcpy(extension, "");  // Sin extensión
    }
    
    free(copia);
}

void Exit(int sig) {
    guard.activo = 0;
    for(int i = 0; i < guard.total_disp; i++) 
    {
        LiberarLista(guard.dispositivos[i].baseline);        
    }
    printf("\n🛑 Sistema MatCom Guard detenido\n");
    exit(0);
}

