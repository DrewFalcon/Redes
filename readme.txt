Autores: Carlos Mendez & Andrés Falcón



Criterios de Evaluación 
----------------------------------------------------------------------------

- Recibir tramas Ethernet, realizar comprobaciones y llamar correctamente a la función de callback de nivel superior:
	- REALIZADO
    - 

- Enviar tramas Ethernet  correctamente:
	- REALIZADO
	- Utiliza una cabecera de 14 bytes de destino + origen MAC + Ethertype (que usamos 0x0806)

- Imprimir mensajes sobre el protocolo 0x0AA0:
	- REALIZADO
    - en la funcion process_ethMsg_frame de ethmsg.py, 

- Enviar correctamente peticiones ARP: 
	- REALIZADO
    - en createARPRequest de arp.py, se devuelve una peticion con el opcode 0x001 para llamar a ARPRequest, y los valores Ip y MAC del ordenador que envio la peticion
    - el MAC a buscar se implementa inicializado a 0 (al ser desconocido)
    - se envian de manera broadcast con el Ethertype 0x0806
    - ARPResolution hace hasta 3 peticiones ARP gratuito

- Procesar correctamente peticiones ARP recibidas: 
	- REALIZADO
    - en processARPRequest, se extrae el IPdestino, IP y MAC origen; Y si todo esta en orden se envia la peticion con sendEthernetFrame despues de haber llamado a createReply
	- en createARPReply, se asigna al opcode 0x002 y se crea una respuesta con createARPRequest que enviara al solicitante
    

- Enviar correctamente respuestas ARP:
    - REALIZADO
	- en createARPReply, se crea una peticion con opcode 0x002 y su IP+MAC más el IP y MAC del solicitante que se dieron como el nuevo target


- Procesar correctamente respuestas ARP :
	- REALIZADO
    - processARPReply actualiza el MAC destino, despues de haber comprobado que los IP/MAC origen y destino no causaran conflictos
    - Añade el MAC resuelto al cache, actualiza el awaitingResponse a False y el requestedIP a None

	


- Manejo correcto de la caché ARP
	- REALIZADO
    - se ha usado la sentencia "with x:" para bloquear temporalmente otros procesos e hilos cuando se quiere modificar una variable global, protegiendo la estructura de conflictos
    - en particuar, se utilizo "with cachelock" para que no hayan conflictos al modificar el cache de Ip/MAC's 

---------------------
Creacion de una funcion extra: "gratuitousARP()"
    - Esta funcion revisa si hay alguna IP duplicada
    - Para evitar repeticiones de codigo al ser usado fuera de initARP, se decidio contener en una funcion.
    - Se ha implementado la opcion de leer desde el teclado para que el usuario pueda ejecutar esta funcionalidad en cualquier momento.




---------------------
Ejecucion de pruebas
    - En las pruebas hemos visto que