# -*- coding: utf-8 -*-
"""
Created on Fri Oct 21 21:31:49 2022

@author: elias
"""

from socket import *
from math import pow
import random
from secrets import token_bytes
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
import ast
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes


#CONEXION Y DEFINICION DE VARIABLES
direccionServidor = "localhost"
puertoservidor = 1234
#Generamos un nuevo socket y establecemos la conexion
socketServidor = socket(AF_INET, SOCK_STREAM)
#Establacemos la conexion
socketServidor.bind((direccionServidor,puertoservidor ))
#escuchamos al servidor
socketServidor.listen()
#variables para el diffie helman
l= ['P','G','b']
elgam=[]
d=dict()
n=0


while True:
    try:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        break
    except ValueError:
        pass

def encrypt(msg):
    cipher = DES3.new(key, DES3.MODE_EAX)
    nonce = cipher.nonce
    ciphertext = cipher.encrypt(msg.encode('ascii'))
    return nonce, ciphertext

def decrypt(nonce, ciphertext):
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('ascii')

def RS():
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator) 

    publickey = key.publickey()

    encryptor = PKCS1_OAEP.new(publickey)
    
    file = open("mensajeentrada.txt", "r")
    mensaje_entrada = str(file.readline().lower()).encode()
    file.close()
    
    mensaje_codificado = encryptor.encrypt(mensaje_entrada)

    file = open("mensajecifrado.txt", "w+")
    file.write(str(mensaje_codificado))
    file.close()


    decryptor = PKCS1_OAEP.new(key)
    mensaje_recibido = decryptor.decrypt(ast.literal_eval(str(mensaje_codificado)))

    file = open("mensajerecibido.txt", "w+")
    file.write(str(mensaje_recibido).decode())
    file.close()
    return


def AS():
    key = token_bytes(16)
    
    file = open("mensajeentrada.txt", "r")
    mensaje_entrada = str(file.readline().lower()).encode()
    file.close()
    
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(mensaje_entrada)

    mensaje_codificado = cipher.nonce + tag + ciphertext
    
    file = open("mensajecifrado.txt", "w+")
    file.write(str(mensaje_codificado))
    file.close()
    
    nonce = mensaje_codificado[:AES.block_size]
    tag = mensaje_codificado[AES.block_size:AES.block_size * 2]
    ciphertext = mensaje_codificado[AES.block_size * 2:]

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    
    mensaje_recibido=cipher.decrypt_and_verify(ciphertext, tag).decode()
    
    file = open("mensajerecibido.txt", "w+")
    file.write(str(mensaje_recibido))
    file.close()
    return

def TDS():
    file = open("mensajeentrada.txt", "r")
    mensaje_entrada = str(file.readline().lower())
    file.close()
    
    nonce, ciphertext= encrypt(mensaje_entrada)
    mensaje_codificado= nonce, ciphertext
    
    file = open("mensajecifrado.txt", "w+")
    file.write(str(mensaje_codificado))
    file.close()
    
    plaintext = decrypt(nonce, ciphertext)
    file = open("mensajerecibido.txt", "w+")
    file.write(plaintext)
    file.close()
    
    return

def mcd(x,y):
    mcd = 1
    
    if x % y == 0:
        return y
    
    for k in range(int(y/2), 0, -1):
        if x % k == 0 and y % k == 0:
            mcd = k
            break
    return mcd



def DS():
   key = token_bytes(8)    #(solo 8)
   iv = token_bytes(8)    # Vector de inicialización
   
   file = open("mensajeentrada.txt", "r")
   mensaje_entrada = str(file.readline().lower()).encode()
   file.close()
   
   cipher1 = DES.new(key, DES.MODE_CFB, iv)
   mensaje_codificado = cipher1.encrypt(mensaje_entrada)
   
   file = open("mensajecifrado.txt", "w+")
   file.write(str(mensaje_codificado))
   file.close()
   
   cipher2 = DES.new(key, DES.MODE_CFB, iv)
   mensaje_recibido = cipher2.decrypt(mensaje_codificado).decode()
   file = open("mensajerecibido.txt", "w+")
   file.write(mensaje_recibido)
   file.close()
   return
    
def elgamal(p,b):
    
    file = open("mensajeentrada.txt", "r")
    mensaje_entrada = float(file.readline().lower())
    file.close()
    
    
    g=12
    a=4
    k=float(pow(g,a)%p)
    y1=pow(g,b)%p
    y2=float((pow(k,b)*mensaje_entrada)%p)
    cifrado=(y1,y2)
    print("el cifrado es: ", cifrado)
    
    decifrado=((pow(y1,(p-1-a)))*y2)%p
    
    file = open("mensajerecibido.txt", "w+")
    file.write(str(decifrado))
    file.close()
    
    
    return
    
    
def dh(d):
    #variables para diffie helman
    #llave privada del server
    a= random.randint(0,(d['P']-1))
    # se obtiene la llave generada para el servidor
    A = int(pow(d['G'],a,d['P'])) 
    # se obtiene la llave generada por el cliente
    B = int(pow(d['G'],d['b'],d['P'])) 
    # llave secreta del servidor
    ka = int(pow(B,a,d['P']))
     
    # llave secreta del cliente
    kb = int(pow(A,d['b'],d['P']))
    if kb==ka:
        return True
    return False

#recibimos las solicitudes
while True:
      #establecemos la conexion con la direccion del cliente y la conexion en si
      socketConexion, addr = socketServidor.accept()
      #se conecto correctamente
      print("Conectado con un cliente", addr)
      #inicia la interaccion de mensajes
      while True:
          #recibe la cadena que envio el cliente mediante la funcion recv
          mensajeRecibido = socketConexion.recv(4096).decode()
          print(mensajeRecibido)
          elgam.append(int(mensajeRecibido))
          # d[l[n]]=int(mensajeRecibido)
          n+=1
          #si n=2 quiere decir que ya tenemos todos los datos necesarios para el df
          if n==2:
              #le avisamos al cliente que las llaves coinciden
              socketConexion.send("llaves generadas".encode())
              #se cifra el mensaje que este en el txt
              p=elgam[0]
              b=elgam[1]
              elgamal(p,b)
              #se le envia el mensaje que se cifro correctamente
              socketConexion.send('mensaje cifrado correctamente'.encode())#arreglar este send no lo muestra el cliente
                  
          #si la cadena es adios salimos del chat
          if mensajeRecibido == 'x':
              break
      break #arreglar este break pendiente.
print("Desconectado el cliente", addr)
#cerramos conexion
socketConexion.close()      


