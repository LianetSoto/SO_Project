#include <gtk/gtk.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <glib-unix.h>
#include <dirent.h>    
#include <ctype.h>    
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_LOG_SIZE 10000

GtkWidget *text_view;

GtkWidget *entry;
GtkTextBuffer *buffer_procesos;
GtkTextBuffer *buffer_archivos;
GtkTextBuffer *buffer_anomalias_puertos;
GtkTextBuffer *buffer_anomalias_dispositivos;
GtkTextBuffer *buffer_dispositivos;
GtkTextBuffer *buffer_puertos;

// Variables para el monitoreo del log
static gint log_fd = -1;
static gsize last_size = 0;
static guint watch_id = 0;

static GString *log_buffer = NULL;
static gboolean new_log_entries = FALSE;


//Monitoreo Constante del Uso de Recursos de Procesos e Hilos

void actualizar_lista_procesos() {
    DIR *dir;
    struct dirent *ent;
    GString *procesos = g_string_new(NULL);
    
    gtk_text_buffer_set_text(buffer_archivos, "", -1);
    
    if ((dir = opendir("/proc")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_DIR && isdigit(ent->d_name[0])) {
               	char name[256]; 
				char cmdline[256];
				char path[PATH_MAX];  
				snprintf(path, sizeof(path), "/proc/%s/status", ent->d_name);

				if (strlen(ent->d_name) > (PATH_MAX - strlen("/proc//status"))) {
					fprintf(stderr, "PID demasiado largo: %s\n", ent->d_name);
					continue;  
				}
                
                FILE *fp = fopen(path, "r");
                if (fp) {
                    if (fgets(name, sizeof(name), fp)) {
                        char *nombre = strchr(name, '\t');
                        if (nombre) {
                            nombre++;
                            nombre[strcspn(nombre, "\n")] = 0;
                            
                            snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
                            FILE *cmd = fopen(path, "r");
                            if (cmd) {
                                fgets(cmdline, sizeof(cmdline), cmd);
                                fclose(cmd);
                                cmdline[strcspn(cmdline, "\n")] = 0;
                                
                                for (char *p = cmdline; *p; p++) {
                                    if (*p == '\0') *p = ' ';
                                }
                            } else {
                                strcpy(cmdline, "[No disponible]");
                            }
                            
                            if (strstr(cmdline, "guardian") == NULL && 
                                strstr(cmdline, "interfaz") == NULL) {
                                g_string_append_printf(procesos, "PID: %s\nNombre: %s\nComando: %s\n\n", 
                                                     ent->d_name, nombre, cmdline);
                            }
                        }
                    }
                    fclose(fp);
                }
            }
        }
        closedir(dir);
    }
    
    gtk_text_buffer_set_text(buffer_archivos, procesos->str, -1);
    g_string_free(procesos, TRUE);
}

void mostrar_alertas_nuevas(GtkTextBuffer *buffer) {
    if (log_buffer != NULL && new_log_entries) {
        gtk_text_buffer_set_text(buffer, log_buffer->str, -1);
        new_log_entries = FALSE;  // Resetear el flag
    } else {
        gtk_text_buffer_set_text(buffer, "No hay alertas nuevas", -1);
    }
}

gboolean monitorear_log(gpointer user_data) {
    struct stat st;
    if (fstat(log_fd, &st)) {
        perror("fstat");
        return TRUE;
    }

    if (st.st_size > last_size) {
        gsize bytes_to_read = st.st_size - last_size;
        gchar *buffer = g_malloc(bytes_to_read + 1);
        
        if (pread(log_fd, buffer, bytes_to_read, last_size) != bytes_to_read) {
            perror("pread");
            g_free(buffer);
            return TRUE;
        }
        
        buffer[bytes_to_read] = '\0';
        
        if (log_buffer == NULL) {
            log_buffer = g_string_new(buffer);
        } else {
            g_string_append(log_buffer, buffer);
            if (log_buffer->len > MAX_LOG_SIZE) {
                gchar* start = strchr(log_buffer->str + (log_buffer->len - MAX_LOG_SIZE), '\n');
                if (start) {
                    g_string_erase(log_buffer, 0, start - log_buffer->str + 1);
                } else {
                    g_string_erase(log_buffer, 0, log_buffer->len - MAX_LOG_SIZE);
                }
            }
        }
        
        new_log_entries = TRUE;
        
        gtk_text_buffer_set_text(buffer_procesos, "", -1);
        
        GtkTextIter start;
        gtk_text_buffer_get_start_iter(buffer_procesos, &start);
        gtk_text_buffer_insert(buffer_procesos, &start, buffer, -1);
        
        GtkTextView *view = GTK_TEXT_VIEW(user_data);
        GtkWidget *parent = gtk_widget_get_parent(GTK_WIDGET(view));
        
        if (GTK_IS_SCROLLED_WINDOW(parent)) {
            GtkScrolledWindow *scrolled_window = GTK_SCROLLED_WINDOW(parent);
            GtkAdjustment *adj = gtk_scrolled_window_get_vadjustment(scrolled_window);
            
            if (adj) {
                gtk_adjustment_set_value(adj, gtk_adjustment_get_upper(adj) - gtk_adjustment_get_page_size(adj));
            }
        }
        
        g_free(buffer);
        last_size = st.st_size;
    }
    else if (st.st_size < last_size) {
        last_size = 0;
        gtk_text_buffer_set_text(buffer_procesos, "", -1);
    }
    
    static time_t last_update = 0;
    time_t now = time(NULL);
    
    if (difftime(now, last_update) >= 3.0) { 
        actualizar_lista_procesos();
        last_update = now;
    }
    
    return TRUE;
}

void iniciar_monitoreo_log(GtkTextView *text_view) {
    const gchar *log_path = "/var/log/guardian_procesos.log";
    
    if (access(log_path, F_OK)) {
        int fd = creat(log_path, 0644);
        if (fd != -1) close(fd);
    }
    
    log_fd = open(log_path, O_RDONLY);
    if (log_fd == -1) {
        perror("open");
        return;
    }
    
    struct stat st;
    if (fstat(log_fd, &st)) {
        perror("fstat");
        close(log_fd);
        log_fd = -1;
        return;
    }
    last_size = st.st_size;
    
    watch_id = g_timeout_add(500, monitorear_log, text_view); 
}

void leer_log_procesos(GtkTextBuffer *buffer) {
    FILE *log = fopen("/var/log/guardian_procesos.log", "r");
    if (log) {
        fseek(log, 0, SEEK_END);
        long size = ftell(log);
        fseek(log, 0, SEEK_SET);
        
        char *content = malloc(size + 1);
        fread(content, 1, size, log);
        content[size] = '\0';
        fclose(log);
        
        gtk_text_buffer_set_text(buffer, content, -1);
        free(content);
    } else {
        gtk_text_buffer_set_text(buffer, "No hay alertas de procesos aún", -1);
    }
}

//Escaneo de Puertos Locales

void cargar_puertos_abiertos() {
    FILE *f = fopen("/tmp/puertos_abiertos.dat", "r");
    if (!f) {
        gtk_text_buffer_set_text(buffer_puertos, "Esperando datos...", -1);
        gtk_text_buffer_set_text(buffer_anomalias_puertos, "Esperando datos...", -1);
        return;
    }
    
    GString *puertos_text = g_string_new(NULL);
    GString *anomalias_text = g_string_new(NULL);
    char line[1024];
    
    while (fgets(line, sizeof(line), f)) {
        // Parsear la línea
        char *port = strtok(line, "|");
        char *service = strtok(NULL, "|");
        char *desc = strtok(NULL, "|");
        char *anom = strtok(NULL, "\n");
        
        if (port && service && desc) {
            // Agregar a lista de puertos
            g_string_append_printf(puertos_text, "Puerto: %s/%s\n%s\n\n", port, service, desc);
            
            // Procesar anomalías
            if (anom) {
                char *token = strtok(anom, ",");
                
                while (token) {
                    // Mapear códigos a descripciones (sin usar enum de project.c)
                    const char *desc_anom = "Anomalía desconocida";
                    switch(atoi(token)) {
                        case 1: desc_anom = "Puerto no registrado"; break;
                        case 2: desc_anom = "No en whitelist"; break;
                        case 3: desc_anom = "Posible Backdoor"; break;
                        case 4: desc_anom = "Puerto de malware"; break;
                        case 5: desc_anom = "Metasploit default"; break;
                    }
                    g_string_append_printf(anomalias_text, "[!] Puerto %s: %s\n", port, desc_anom);
                    token = strtok(NULL, ";");
                }
            }
        }
    }
    fclose(f);
    
    gtk_text_buffer_set_text(buffer_puertos, puertos_text->str, -1);  // Cuadro de Puertos Abiertos
    gtk_text_buffer_set_text(buffer_anomalias_puertos, 
                            (anomalias_text->len > 0) ? anomalias_text->str : "Sin anomalías detectadas", 
                            -1);  // Cuadro de Anomalías de Puertos
    
    
    g_string_free(puertos_text, TRUE);
    g_string_free(anomalias_text, TRUE);
}

gboolean actualizar_puertos(gpointer user_data) {
    cargar_puertos_abiertos();
    return TRUE;  // Mantener activo
}

//Detección y Escaneo de Dispositivos Conectados

void cargar_dispositivos() {
    // Dispositivos conectados
    FILE *f = fopen("/tmp/dispositivos.dat", "r");
    if (f) {
        char content[4096];
        size_t len = fread(content, 1, sizeof(content), f);
        content[len] = '\0';
        fclose(f);
        gtk_text_buffer_set_text(buffer_dispositivos, content, -1);
    } else {
        gtk_text_buffer_set_text(buffer_dispositivos, "Esperando datos de dispositivos...", -1);
    }

    // Anomalías de dispositivos
    f = fopen("/tmp/anomalias_dispositivos.dat", "r");
    if (f) {
        char content[4096];
        size_t len = fread(content, 1, sizeof(content), f);
        content[len] = '\0';
        fclose(f);
        gtk_text_buffer_set_text(buffer_anomalias_dispositivos, content, -1);
    } else {
        gtk_text_buffer_set_text(buffer_anomalias_dispositivos, "Sin anomalías en dispositivos", -1);
    }
}

gboolean actualizar_dispositivos(gpointer user_data) {
    cargar_dispositivos();
    return TRUE;  // Mantener activo
}


void apply_css(GtkWidget *widget, GtkStyleProvider *provider) {
	gtk_style_context_add_provider(gtk_widget_get_style_context(widget),
				provider,
				G_MAXUINT);
if(GTK_IS_CONTAINER(widget)) {
	gtk_container_forall(GTK_CONTAINER(widget),
		(GtkCallback)apply_css,
		provider);
}
}

//Funciones botones

static void on_scan_devices(GtkWidget *widget, gpointer data) {
    cargar_dispositivos();
}

static void on_scan_filesystem(GtkWidget *widget, gpointer data) {
	mostrar_alertas_nuevas(buffer_procesos);
}

static void on_scan_ports(GtkWidget *widget, gpointer data) {
    cargar_puertos_abiertos(); // Solo actualiza desde el archivo
}

static void on_scan_all(GtkWidget *widget, gpointer data) {
    on_scan_filesystem(widget, data);
    on_scan_devices(widget, data);
    cargar_puertos_abiertos();
	mostrar_alertas_nuevas(buffer_procesos);
}



static void activate(GtkApplication *app, gpointer user_data) {
     GtkWidget *window;
    GtkWidget *grid;
    GtkWidget *button;
    GtkWidget *main_box;
    GtkWidget *results_box;
    GtkCssProvider *provider;
    
    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Gran Salón del Trono - Monitor del Reino");
    gtk_window_set_default_size(GTK_WINDOW(window), 50, 400);
    
    provider = gtk_css_provider_new();
    gtk_css_provider_load_from_data(provider, 
        "window, box, grid { background-color: #d8e8f8;}"
        "textview {"
        "   background: #f0f8ff;"
        "   color: #1a3a5a;"
        "}"
        "button {"
        "   background-color: #1e3c5a;"
        "   color: white;"
        "   border-radius: 8px;"
        "   padding: 12px;"
        "   margin: 5px;"
        "   font-weight: bold;"
        "}"
        "button:hover {"
        "   background-color: #8fb6d1;"
        "   transition: 0.3s;"
        "}"
        "result-frame {"
        "   min-width: 280px;"
        "   max-width: 280px;"
        "   min-height: 400px;"
        "   max-height: 400px;"
        "}", -1, NULL);

    main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), main_box);
    apply_css(main_box, GTK_STYLE_PROVIDER(provider)); 
    
    results_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    
    GtkWidget *col1_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    
    // DERECHA-SECCIÓN SUPERIOR: MONITOR DE ALERTAS
    GtkWidget *frame_procesos = gtk_frame_new("Alertas de Procesos");
    GtkWidget *box_procesos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *label_procesos = gtk_label_new("Procesos con alto consumo");
    gtk_widget_set_name(label_procesos, "result-title");
    
    GtkWidget *scrolled_procesos = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scrolled_procesos, 280, 180);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_procesos),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    
    GtkWidget *text_procesos = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_procesos), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_procesos), TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled_procesos), text_procesos);
     
    gtk_box_pack_start(GTK_BOX(box_procesos), label_procesos, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_procesos), scrolled_procesos, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(frame_procesos), box_procesos);
    gtk_box_pack_start(GTK_BOX(col1_container), frame_procesos, TRUE, TRUE, 0);
    
    // DERECHA-SECCIÓN INFERIOR: PROCESOS EN EJECUCIÓN
    GtkWidget *frame_archivos = gtk_frame_new("Procesos en Ejecución");
    GtkWidget *box_archivos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *label_archivos = gtk_label_new("Todos los procesos activos");
    gtk_widget_set_name(label_archivos, "result-title");
    
    GtkWidget *scrolled_archivos = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scrolled_archivos, 280, 180);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_archivos),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    
    GtkWidget *text_archivos = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_archivos), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_archivos), TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled_archivos), text_archivos);
    
    gtk_box_pack_start(GTK_BOX(box_archivos), label_archivos, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_archivos), scrolled_archivos, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(frame_archivos), box_archivos);
    gtk_box_pack_start(GTK_BOX(col1_container), frame_archivos, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(results_box), col1_container, TRUE, TRUE, 0);

    GtkWidget *col2_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    
    // MEDIO-SECCIÓN SUPERIOR: ANOMALÍAS DE PUERTOS
    GtkWidget *frame_anomalias_puertos = gtk_frame_new("Anomalías de Puertos");
    GtkWidget *box_anomalias_puertos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *label_anomalias_puertos = gtk_label_new("Actividad sospechosa en puertos");
    gtk_widget_set_name(label_anomalias_puertos, "result-title");
    
    GtkWidget *scrolled_anomalias_puertos = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scrolled_anomalias_puertos, 280, 180);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_anomalias_puertos),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    
    GtkWidget *text_anomalias_puertos = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_anomalias_puertos), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_anomalias_puertos), TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled_anomalias_puertos), text_anomalias_puertos);
    
    gtk_box_pack_start(GTK_BOX(box_anomalias_puertos), label_anomalias_puertos, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_anomalias_puertos), scrolled_anomalias_puertos, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(frame_anomalias_puertos), box_anomalias_puertos);
    gtk_box_pack_start(GTK_BOX(col2_container), frame_anomalias_puertos, TRUE, TRUE, 0);
    
    // MEDIO-SECCIÓN INFERIOR: PUERTOS ABIERTOS
    GtkWidget *frame_puertos = gtk_frame_new("Puertos Abiertos");
    GtkWidget *box_puertos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *label_puertos = gtk_label_new("Todos los puertos activos");
    gtk_widget_set_name(label_puertos, "result-title");
    
    GtkWidget *scrolled_puertos = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scrolled_puertos, 280, 180);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_puertos),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    
    GtkWidget *text_puertos = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_puertos), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_puertos), TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled_puertos), text_puertos);
    
    gtk_box_pack_start(GTK_BOX(box_puertos), label_puertos, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_puertos), scrolled_puertos, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(frame_puertos), box_puertos);
    gtk_box_pack_start(GTK_BOX(col2_container), frame_puertos, TRUE, TRUE, 0);
    
    gtk_box_pack_start(GTK_BOX(results_box), col2_container, TRUE, TRUE, 0);
    
    GtkWidget *col3_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    
    // IZQUIERDA-SECCIÓN SUPERIOR: ANOMALÍAS DE DISPOSITIVOS
    GtkWidget *frame_anomalias_dispositivos = gtk_frame_new("Anomalías de Dispositivos");
    GtkWidget *box_anomalias_dispositivos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *label_anomalias_dispositivos = gtk_label_new("Dispositivos sospechosos");
    gtk_widget_set_name(label_anomalias_dispositivos, "result-title");
    
    GtkWidget *scrolled_anomalias_dispositivos = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scrolled_anomalias_dispositivos, 280, 180);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_anomalias_dispositivos),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    
    GtkWidget *text_anomalias_dispositivos = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_anomalias_dispositivos), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_anomalias_dispositivos), TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled_anomalias_dispositivos), text_anomalias_dispositivos);
    
    gtk_box_pack_start(GTK_BOX(box_anomalias_dispositivos), label_anomalias_dispositivos, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_anomalias_dispositivos), scrolled_anomalias_dispositivos, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(frame_anomalias_dispositivos), box_anomalias_dispositivos);
    gtk_box_pack_start(GTK_BOX(col3_container), frame_anomalias_dispositivos, TRUE, TRUE, 0);
    
    // IZQUIERDA-SECCIÓN INFERIOR: DISPOSITIVOS
    GtkWidget *frame_dispositivos = gtk_frame_new("Dispositivos Conectados");
    GtkWidget *box_dispositivos = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    GtkWidget *label_dispositivos = gtk_label_new("Todos los dispositivos");
    gtk_widget_set_name(label_dispositivos, "result-title");
    
    GtkWidget *scrolled_dispositivos = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(scrolled_dispositivos, 280, 180);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_dispositivos),
            GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    
    GtkWidget *text_dispositivos = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text_dispositivos), FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(text_dispositivos), TRUE);
    gtk_container_add(GTK_CONTAINER(scrolled_dispositivos), text_dispositivos);
    
    gtk_box_pack_start(GTK_BOX(box_dispositivos), label_dispositivos, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(box_dispositivos), scrolled_dispositivos, TRUE, TRUE, 0);
    gtk_container_add(GTK_CONTAINER(frame_dispositivos), box_dispositivos);
    gtk_box_pack_start(GTK_BOX(col3_container), frame_dispositivos, TRUE, TRUE, 0);
    
    gtk_box_pack_start(GTK_BOX(results_box), col3_container, TRUE, TRUE, 0);
    
    //buffers
    buffer_procesos = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_procesos));
    buffer_archivos = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_archivos));
    buffer_anomalias_puertos = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_anomalias_puertos));
    buffer_puertos = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_puertos));
    buffer_anomalias_dispositivos = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_anomalias_dispositivos));
    buffer_dispositivos = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_dispositivos));

    g_timeout_add_seconds(5, actualizar_dispositivos, NULL);
    g_timeout_add_seconds(2, actualizar_puertos, NULL);

    actualizar_lista_procesos(); 
    on_scan_devices(NULL, NULL);  
    on_scan_ports(NULL, NULL);  

    iniciar_monitoreo_log(GTK_TEXT_VIEW(text_procesos));

    gtk_box_pack_start(GTK_BOX(main_box), results_box, TRUE, TRUE, 0);
    
    GtkWidget *buttons_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_margin_bottom(buttons_box, 20);
    gtk_box_set_homogeneous(GTK_BOX(buttons_box), TRUE);
    
    GtkWidget *btn_devices = gtk_button_new_with_label("Escanear sistema de archivos");
    g_signal_connect(btn_devices, "clicked", G_CALLBACK(on_scan_filesystem), NULL);
    gtk_box_pack_start(GTK_BOX(buttons_box), btn_devices, TRUE, TRUE, 0);

    GtkWidget *btn_usb = gtk_button_new_with_label("Escanear memoria");
    g_signal_connect(btn_usb, "clicked", G_CALLBACK(on_scan_devices), NULL);
    gtk_box_pack_start(GTK_BOX(buttons_box), btn_usb, TRUE, TRUE, 0);

    GtkWidget *btn_ports = gtk_button_new_with_label("Escanear puertos");
    g_signal_connect(btn_ports, "clicked", G_CALLBACK(on_scan_ports), NULL);
    gtk_box_pack_start(GTK_BOX(buttons_box), btn_ports, TRUE, TRUE, 0);

    GtkWidget *btn_all = gtk_button_new_with_label("Escanear todo");
    g_signal_connect(btn_all, "clicked", G_CALLBACK(on_scan_all), NULL);
    gtk_box_pack_start(GTK_BOX(buttons_box), btn_all, TRUE, TRUE, 0);
    
    gtk_box_pack_start(GTK_BOX(main_box), buttons_box, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
}

static void cerrar_aplicacion(GtkWidget *widget, gpointer data) {
    if (log_fd != -1) {
        close(log_fd);
        log_fd = -1;
    }
    
    if (watch_id) {
        g_source_remove(watch_id);
        watch_id = 0;
    }
    
    gtk_main_quit();
}

int main(int argc, char **argv) {

    
    system("touch /tmp/puertos_abiertos.dat");
    system("chmod 666 /tmp/puertos_abiertos.dat");

    GtkApplication *app;
    int status;
    
    struct stat st = {0};
    if (stat("/var/log", &st) == -1) {
        mkdir("/var/log", 0755);
    }

    FILE *f = fopen("/tmp/puertos_abiertos.dat", "w");
    if (f) {
        fprintf(f, "Esperando datos...\n");
        fclose(f);
        system("chmod 666 /tmp/puertos_abiertos.dat");
    } else {
        perror("Error creando archivo temporal");
    }
    if (fork() == 0) {
        execl("./EscaneoDispositivos", "EscaneoDispositivos", NULL);
        exit(0);
    }

    log_buffer = g_string_new(NULL);
    new_log_entries = FALSE;

    
    FILE *log = fopen("/var/log/guardian_puertos.log", "a");
    if (log) fclose(log);
    else perror("No se pudo crear /var/log/guardian_procesos.log");
    
    app = gtk_application_new("reino.monitoreo", G_APPLICATION_FLAGS_NONE);
    
    g_signal_connect(app, "activate", G_CALLBACK(activate), NULL);
    
    status = g_application_run(G_APPLICATION(app), argc, argv);
    
    if (log_fd != -1) {
        close(log_fd);
        log_fd = -1;
    }
    
    if (watch_id) {
        g_source_remove(watch_id);
        watch_id = 0;
    }
    
    g_object_unref(app);
    return status;
}