# -*- coding: utf-8 -*-
"""
Created on Fri Oct 21 21:35:44 2022

@author: elias
"""

from socket import *
import sys



IPServidor = "localhost"
puertoServidor = 1234

#se declara y se inician las conexiones con el servidor 
socketCliente = socket(AF_INET,SOCK_STREAM)
socketCliente.connect((IPServidor,puertoServidor))

while True:
    verificador=input("pulsa cualquier tecla para seguir (ingresar x para salir)")
    if verificador != 'x':
        P = input("ingrese un numero primo P: ")
        socketCliente.send(P.encode())
        key = input("ingrese su llave privada: ")
        socketCliente.send(key.encode())
        
        #recibimos respuesta
        respuesta = socketCliente.recv(4096).decode()
        print(respuesta)
        
            
    else:
        #se manda esta cadena al sv
        socketCliente.send(verificador.encode())
        #cerramos el socket
        socketCliente.close()
        sys.exit()