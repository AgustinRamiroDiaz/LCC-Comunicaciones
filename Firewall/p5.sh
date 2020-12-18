#iptables [-t TABLA] [COMANDO] [FILTRO] [-j ACCION]

#TABLA: filter (por defecto), nat, mangle, raw,...
#COMANDO: -(A)dd, (I)nsert, (D)elete, (F)lush, (P)olicy
#FILTRO: selcciona paquetes
#ACCION: DROP, REJECT (DROPPEA + MENSAJE ICMP), ACCEPT, JUMP, MASQUERADE, REDIRECT, DNAT, SNAT

# Comentarios generales
# -i está disponible es prerouting y forward (interfaz)
# -o está disponibles en postrouting y forward (interfaz)
# -s y -d están siempre disponibles (dirección)
# -m multiport permite definir todos los puertos en una linea
# \ permite continuar en la siguiente linea

# Mail (smtp/s) puerto 25 - 465 / tcp
# BD (mysql) puerto 3306 / tcp
# DNS (dns) puerto 53 / tcp - udp
# Web (http/s) puerto 80 - 443 / tcp
# Acceso remoto (ssh) puerto 22 / tcp
# Proxy Web () puerto 3128 / tcp 




Consultas iptables:

s i, d o necesarios los 2?
corrige optimización?
DMZ necesita NAT? Suponemos IPpúblicas y privadas?
to = to-source, to-destination? Cómo hacemos el DNAT

Consultas:
Manuscrito o digital?
Teórico aparte?






#Ejercicio 20171130
# Notas: algunas lineas se pueden compactar:
  - m multiport
  - for x in tcp udp ; do ...[$x/p] done

#!/bin/bash

#Constantes
IF_INET = eth0
IF_SERV = eth1
IF_LAM = eth2
IF_DMZ = eth3

LAN = 10.23.0.0/16
SERVERS = 10.10.0.0/22
DMZ = 10.1.1.0/29

DBSERVER = 10.10.1.2
MAILSERVER = 10.10.1.3
WEBSERVER = 10.1.1.2
MAILRELAY = 10.1.1.3
INET = 200.3.1.2

I=/sbin/iptables

case $1 in
  start)
  
  # Ej 9 - Se verifica por la política por defecto (-P DROP)
  #Política por defecto: droppear paquetes
  $I -P FORWARD DROP

  #Reglas de estado, se necesitan para un router stateful
  $I -A FORWARD -m state --state INVALID -j DROP
  $I -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  #Si llega hasta acá es porque los paquetes son NEW (xINVALID, xRELATED, xESTABLISHED)

  # TABLA FILTER
  # Ej 8 - La PC de admin (10.23.23.5) de la LAN tiene acceso al firewall (ssh puerto 22)
  # -i evita spoofing en este caso
  $I -A INPUT -s 10.23.23.5 -i $IF_LAN -p tcp --dport 22 -j ACCEPT

  # Ej1 - PCs en LAN tienen acceso al mail server (tcp)
  $I -A FORWARD -m multiport -s $LAN -i $IF_LAN -d $MAILSERVER -o $IF_SERV -p tcp \ --dports imap, imaps, pop, pop3s, smtp, smtp-ssl -j ACCEPT

  # Ej1 - PCs en LAN tienen acceso al dbserver (tcp puerto 443) - [-i $IF_LAM]
  $I -A FORWARD -s $LAN -i $IF_LAN -d $DBSERVER -o $IF_SERV -p tcp --dport 443 -j ACCEPT
  
  # Ej1 - PCs en LAN pueden acceder al DNS de la DMZ (udp puerto 53) - [-i $IF_LAM]
  $I -A FORWARD -s $LAN -i $IF_LAN -d $MAILRELAY -o $IF_DMZ -p udp --dport 53 -j ACCEPT

  # Ej 5 - Las PC de la LAN tienen acceso a internet - Stateful -> SNAT (postrouting)
  $I -A FORWARD -s $LAN -i $IF_LAN -d $INET -o $IF_INET -p tcp --dport 80 -j ACCEPT

  # Ej 1 - "Y a nada más" se verifica por la política por defecto (-P DROP)

  # Ej2 - El servidor de mail tiene acceso al DNS
  $I -A FORWARD -s $MAILSERVER -i $IF_SERV -d $MAILRELAY -o $IF_DMZ -p udp --dport 53 -j ACCEPT
  $I -A FORWARD -s $MAILSERVER -i $IF_SERV -d $MAILRELAY -o $IF_DMZ -p tcp --dport 53 -j ACCEPT

  # Ej 2 - El servidor de mail tiene acceso al MAILRELAY (tcp puerto 465)
  $I -A FORWARD -s $MAILSERVER -i $IF_SERV -d $MAILRELAY -o $IF_DMZ -p tcp --dport 465 -j ACCEPT

  # Ej 3 - El relay tiene acceso al servidor de mail (tcp puerto 465)
  $I -A FORWARD -s $MAILRELAY -i $IF_DMZ -d $MAILSERVER -o $IF_SERV -p tcp --dport 465 -j ACCEPT

  # Ej 4 - El webserver de la DMZ tiene acceso al dbserver (tcp puerto 3306)
  $I -A FORWARD -s $WEBSERVER -i $IF_DMZ -d $DBSERVER -o $IF_SERV -p tcp --dport 3306 -j ACCEPT

  # Ej 6 - Internet tiene acceso a Mailrelay (udp,tcp puerto 53)
  $I -A FORWARD -s $INET -i $IF_INET -d $MAILRELAY -o $IF_DMZ -p tcp --dport 53 -j ACCEPT
  $I -A FORWARD -s $INET -i $IF_INET -d $MAILRELAY -o $IF_DMZ -p udp --dport 53 -j ACCEPT

  # Ej 6 - Internet tiene acceso a Mailrelay (tcp puerto 25)
  $I -A FORWARD -s $INET -i $IF_INET -d $MAILRELAY -o $IF_DMZ -p tcp --dport 25 -j ACCEPT

  # Ej 6 - Internet tiene acceso a Webserver (tcp puerto 80, 443)
  $I -A FORWARD -m multiport -s $INET -i $IF_INET -d $WEBSERVER -o $IF_DMZ -p tcp --dports 80,443 -j ACCEPT

  # Ej 7 - Los servidores de la DMZ tienen acceso a internet (udp,tcp puerto 53)
  $I -A FORWARD -i $IF_DMZ -d $INET -o $IF_INET -p udp --dport 53 -j ACCEPT
  $I -A FORWARD -i $IF_DMZ -d $INET -o $IF_INET -p tcp --dport 53 -j ACCEPT

  # Ej 7 - El relay tiene acceso a internet (tcp puerto 25)
  $I -A FORWARD -s $MAILRELAY -i $IF_DMZ -d $INET -o $IF_INET -p tcp --dport 25 -j ACCEPT

  # TABLA NAT

  # SNAT - POSTROUTING
  # Ej 5 - Nateo de PCs de la LAN a internet
  $I -t nat -A POSTROUTING -s $LAN -d $INET -o $IF_INET -j SNAT -to--source $INET

  # Hacen falta NAT de la DMZ ya que es privada 
  # Ej 7 - Nateo de Servidores de la DMZ a internet
  $I -t nat -A POSTROUTING -s $DMZ -d $INET -o $IF_INET -j SNAT -to--source $INET

  # DNAT - PREROUTING
  # Ej 6 - Nateo 
  $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $MAILRELAY -p tcp --dport 53 -j DNAT -to--destination $MAILRELAY
  $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $MAILRELAY -p udp --dport 53 -j DNAT -to--destination $MAILRELAY
  $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $MAILRELAY -p tcp --dport 25 -j DNAT -to--destination $MAILRELAY
  $I -t nat -A PREROUTING -m multiport -s $INET -i $IF_INET -d $WEBSERVER -p tcp --dports 80,443 -j DNAT -to--destination $WEBSERVER

;;
  stop)
  comandos en caso de stop
;;
  restart)
  comandos en caso de reinicio
;;
  *)
  otro caso
;;
esac










#Ejercicio 20181128

case $1 in
  start)
  
LAN=10.0.1.0/24
    ADMIN=10.0.1.22
DMZ=181.16.1.16/28
    WEB=181.16.1.18
    PROXY=181.16.1.19
INET=200.3.1.2

IF_LAN=eth0
IF_DMZ=eth1
IF_INET=eth2

I=/sbin/iptables

# Limpiamos reglas anteriores
$I -F -t filter
$I -F -t nat

# Tabla FILTER
# Policy
$I -p FORWARD DROP 
# Ej 1
$I -p INPUT DROP 
# Ej 6
$I -p OUTPUT DROP 

# Reglas de estado, se necesitan para un router stateful
$I -A FORWARD -m state --state INVALID -j DROP 
$I -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

$I -A INPUT -m state --state INVALID -j DROP 
$I -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

$I -A OUTPUT -m state --state INVALID -j DROP 
$I -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Ej 1 - Sólo admin puede acceder a shh de servidores 
$I -A FORWARD -s $ADMIN -i $IF_LAN -o $IF_DMZ -p tcp --dport 22 -j ACCEPT

# Ej 1 - Sólo admin puede acceder a shh de firewall 
$I -A INPUT -s $ADMIN -i $IF_LAN -p tcp --dport 22 -j ACCEPT

# Ej 2 - LAN puede acceder al resto de los servicios de la DMZ
# Servidor Web
$I -A FORWARD -s $LAN -i $IF_LAN -d $WEB -o $IF_DMZ -m multiport -p tcp --dports 53, 80, 443 -j ACCEPT
$I -A FORWARD -s $LAN -i $IF_LAN -d $WEB -o $IF_DMZ -p udp --dport 53 -j ACCEPT

# Servidor Proxy
$I -A FORWARD -s $LAN -i $IF_LAN -d $PROXY -o $IF_DMZ -m multiport -p tcp --dports 53, 3128 -j ACCEPT
$I -A FORWARD -s $LAN -i $IF_LAN -d $PROXY -o $IF_DMZ -p udp --dport 53 -j ACCEPT


# Solución alternativa Ej 2
# Regala todos los puertos, no solo los que dan servicios
# inicio
$I -A FORWARD -s $LAN -i $IF_LAN -d $DMZ -o $IF_DMZ -p tcp --dport 22 -j REJECT
$I -A FORWARD -s $LAN -i $IF_LAN -d $DMZ -o $IF_DMZ -p tcp -j ACCEPT
$I -A FORWARD -s $LAN -i $IF_LAN -d $DMZ -o $IF_DMZ -p udp -j ACCEPT
# oicini

# Ej 3 - LAN acceso a Internet de forma directa, excepto web
$I -A FORWARD -s $LAN -i $IF_LAN -d $INET -o $IF_INET -p tcp -m multiport --dports 80, 443 -j REJECT
$I -A FORWARD -s $LAN -i $IF_LAN -d $INET -o $IF_INET -j ACCEPT

# Ej 4 - DMZ solo pueden acceder a servicios DNS y web en Internet
$I -A FORWARD -s $DMZ -i $IF_DMZ -d $INET -o $IF_INET \ 
    -p udp --dport  53 -j ACCEPT
$I -A FORWARD -s $DMZ -i $IF_DMZ -d $INET -o $IF_INET -m multiport \ 
    -p tcp --dports  53, 80, 443 -j ACCEPT
# El resto se verifica con la policy

# Ej 5 - Internet tiene acceso a DNS de ambos servidores
$I -A FORWARD -s $INET -i $IF_INET -d $PROXY -o $IF_DMZ -p udp --dport 53 -j ACCEPT 
$I -A FORWARD -s $INET -i $IF_INET -d $PROXY -o $IF_DMZ -p tcp --dport 53 -j ACCEPT 

$I -A FORWARD -s $INET -i $IF_INET -d $WEB -o $IF_DMZ -p udp --dport 53 -j ACCEPT 
$I -A FORWARD -s $INET -i $IF_INET -d $WEB -o $IF_DMZ -p tcp --dport 53 -j ACCEPT 

# Ej 5 - Internet tiene acceso a la web del servidor Web
$I -A FORWARD -s $INET -i $IF_INET -d $WEB -o $IF_DMZ -m multiport -p tcp \
    --dports 80, 443 -j ACCEPT 

# Ej 6 - Firewall tiene acceso al proxy
$I -A OUTPUT -d $PROXY -o $IF_DMZ -p tcp --dport 3128 -j ACCEPT

# Tabla NAT
# Ej 3
$I -t nat -A POSTROUTING -s $LAN -d $INET -o $IF_INET -j SNAT -to--source $INET

# No hacemos estos nat ya que tienen direcciones públicas
# # Ej 4 
# $I -t nat -A POSTROUTING -s $DMZ -d $INET -o $IF_INET -j SNAT -to--source $INET

# # Ej 5
# $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $DMZ -j DNAT -to $DMZ

;;

stop)
    $I -F -t nat
    $I -F

;;

*)
    echo "Sintaxis: $0 <start|stop>"
    exit 1
;;

esac








# Solución Ejercicio 20201216


case $1 in
  start)
  
LAN=10.0.1.0/24
    ADMIN=10.0.1.22
SERV=10.0.2.0/24
    DB=10.0.2.3
DMZ=181.16.1.16/28
    S1=181.16.1.18  # web, dns
    S2=181.16.1.19  # dns
INET=200.3.1.2

IF_LAN=eth0
IF_SERV=eth1
IF_DMZ=eth2
IF_INET=eth3

I=/sbin/iptables

# Tabla FILTER
# Policy
$I -p FORWARD DROP 

# Reglas de estado, se necesitan para un router stateful
$I -A FORWARD -m state --state INVALID -j DROP 
$I -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# Ej 1 - LAN no tiene acceso a servidores
$I -A FORWARD -s $LAN -i $IF_LAN -d $SERV -o $IF_SERV -j REJECT
# Ej 1 - LAN tiene acceso al resto (REQUIERE NAT)
$I -A FORWARD -s $LAN -i $IF_LAN -j ACCEPT

# Ej 2 - Internet tiene acceso a DMZ (tcp y udp 53 de ambos servidores) (REQUIERE NAT)
# Suponemos que "exterior" significa desde afuera de nuestra red = Internet
for protocolo in udp, tcp; do
    $I -A FORWARD -s $INET -i $IF_INET -d $S1 -o $IF_DMZ -p protocolo --dport 53 -j ACCEPT
    $I -A FORWARD -s $INET -i $IF_INET -d $S2 -o $IF_DMZ -p protocolo --dport 53 -j ACCEPT
done

# Ej 2 - Internet tiene acceso al servidor web (S1) (puertos 80 y 443) (REQUIERE NAT)
$I -A FORWARD -s $INET -i $IF_INET -d $S1 -o $IF_DMZ -m multiport \ 
    -p tcp --dports 80, 443 -j ACCEPT

# Ej 3 - DMZ tiene acceso a Internet (dns) (REQUIERE NAT)
# Suponemos que "exterior" significa desde afuera de nuestra red = Internet
$I -A FORWARD -s $DMZ -i $IF_DMZ -d $INET -o $IF_INET -p udp --dport 53 -j ACCEPT
$I -A FORWARD -s $DMZ -i $IF_DMZ -d $INET -o $IF_INET -p tcp --dport 53 -j ACCEPT

# Ej 3 - DMZ tiene acceso a db (mysql: tcp 3306)
$I -A FORWARD -s $DMZ -i $IF_DMZ -d $DB -o $IF_SERV -p tcp --dport 3306 -j ACCEPT

# Ej 4 - La red de Servers no tiene ningún tipo de acceso (excepto para responder al servidor web)
# no es necesaria por la policy si quisiera droppear
$I -A FORWARD -s $SERV -i $IF_SERV -j REJECT
# No se aceptan nuevas conexiones (recordar que a partir del stateful, solamente trabajamos con NEW)
# $I -A FORWARD -s $SERV -i $IF_SERV -d $S1 -o $IF_SERV -j ACCEPT



# Tabla NAT
# Ej 1
$I -t nat -A POSTROUTING -s $LAN -d $INET -o $IF_INET -j SNAT -to $INET

# No hacemos estos nat ya que tienen direcciones públicas
# # Ej 2
# for protocolo in udp, tcp; do
#     $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $S1 -p protocolo --dport 53 -j DNAT -to $S1
#     $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $S2 -p protocolo --dport 53 -j DNAT -to $S2
# done

# $I -t nat -A PREROUTING -s $INET -i $IF_INET -d $S1 -m multiport \ 
#     -p tcp --dports 80, 443 -j DNAT -to $S1

# # Ej 3
# $I -t nat -A POSTROUTING -s $DMZ -d $INET -o $IF_INET -p tcp --dport 53 -j SNAT -to $INET
# $I -t nat -A POSTROUTING -s $DMZ -d $INET -o $IF_INET -p udp --dport 53 -j SNAT -to $INET

;;

	stop)
	$I -P INPUT ACCEPT
	$I -F 
	$I -F -t nat
;;
	restart)
	$0 stop
	$0 start
;;
	*)

	echo "Error de sintaxis"

	;;
esac
	