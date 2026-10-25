PRACTICA 2 - REDES DE COMUNICACIONES - UAM
Autores: Carlos Mendez & Andrés Falcón
Grupo:
Pareja:

Criterios de Evaluación 
----------------------------------------------------------------------------

1. Recibir tramas Ethernet, realizar comprobaciones y llamar correctamente a la función de callback de nivel superior:
    - REALIZADO
    - Si el Ethertype está en EthernetProtocols, se llama al callback con el header, us, srcMac enviado y el payload

2. Enviar tramas Ethernet  correctamente:
    - REALIZADO
    - En sendEthernetFrame se construye la trama con los valores dstMac + myMAC + Ethertype + 
    - Envía dicha trama con pcap_inject y comprueba que el tamaño de la trama es igual al número de bytes transmitidos

3. Imprimir mensajes sobre el protocolo 0x0AA0:
    - REALIZADO
    - en la función process_ethMsg_frame se lee la longitud del mensaje y se extrae de data
    - Se imprime el mensaje obtenido con la fecha y hora más su header.ts, la MAC origen y la longitud

4. Enviar correctamente peticiones ARP: 
    - REALIZADO
    - en createARPRequest de arp.py, se devuelve una petición con el opcode 0x001 para llamar a ARPRequest, y los valores Ip y MAC del ordenador que envía la petición
    - el MAC a buscar se implementa inicializado a 0 (al ser desconocido)
    - se envían de manera broadcast con el Ethertype 0x0806
    - ARPResolution hace hasta 3 peticiones ARP gratuito

5. Procesar correctamente peticiones ARP recibidas: 
    - REALIZADO
    - en processARPRequest, se extrae el IPdestino, IP y MAC origen; Y si todo está en orden se envía la petición con sendEthernetFrame después de haber llamado a createReply
    - en createARPReply, se asigna al opcode 0x002 y se crea una respuesta con createARPRequest que enviará al solicitante
    

6. Enviar correctamente respuestas ARP:
    - REALIZADO
    - en createARPReply, se crea una petición con opcode 0x002 y su IP+MAC más el IP y MAC del solicitante que se dieron como el nuevo target


7. Procesar correctamente respuestas ARP :
    - REALIZADO
    - processARPReply actualiza el MAC destino, después de haber comprobado que los IP/MAC origen y destino no causarán conflictos
    - Añade el MAC resuelto al cache, actualiza el awaitingResponse a False y el requestedIP a None

    
8. Manejo correcto de la caché ARP
    - REALIZADO
    - se ha usado la sentencia "with x:" para bloquear temporalmente otros procesos e hilos cuando se quiere modificar una variable global, protegiendo la estructura de conflictos
    - en particular, se utilizó "with cachelock" para que no hayan conflictos al modificar el caché de Ip/MAC's 

---------------------
Observaciones:
    .Creación de una función extra: "gratuitousARP()"
        - Esta función revisa si hay alguna IP duplicada
        - Para evitar repeticiones de código al ser usado fuera de initARP, se decidió contener en una función.
        - Se ha implementado la opción de leer desde el teclado para que el usuario pueda ejecutar esta funcionalidad en cualquier momento.

    .Se ha utilizado el EtherType 0x0AA0 para el protocolo de mensajes Ethernet, siguiendo el enunciado de la práctica, aunque en el código inicial proporcionado figuraba 0x3003.


---------------------
Ejecución de pruebas
    - En las pruebas hemos visto que