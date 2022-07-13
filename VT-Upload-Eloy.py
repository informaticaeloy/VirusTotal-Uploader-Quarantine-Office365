
import requests
import json
import datetime


## PREPARACIÓN DEL ENTORNO PARA SUBIR UN FICHERO A VT
url_upload = "https://www.virustotal.com/api/v3/files"

files = {"file": open("Transaction.doc", "rb")}
headers = {
    "Accept": "application/json",
    "x-apikey": "dc586b6cfake2f46da6a259f231ee697529375925fakeb1d95400459a4a3e925"
}
ID_de_la_coleccion = "9554826dd994ffake8b5aeb43eb010b041865cf5cafake5880b64283ca04567b"
ahora = datetime.datetime.now()
nueva_descripcion = "Mis detecciones de Malware en Office365 -> Last Update : "+str(ahora.strftime("%a, %d-%b-%Y %H:%M:%S CET"))
## SUBIMOS EL FICHERO E IMPRIMIMOS LA RESPUESTA POR PANTALLA
response = requests.post(url_upload, files=files, headers=headers)
print(response.text)

## DEVUELVE ALGO SIMILAR A ESTO:
## {
##     "data": {
##         "type": "analysis",
##         "id": "OGNlM2I4NWM2NjNkYzY1NzM2NDYwNTg3Y2MxMDNiYjM6MTY1NzAzNjA0NA=="
##     }
## }


## PARSEAMOS LA RESPUESTA OBTENIDA PARA OBTENER EL ID DE LA SUBIDA
datos=json.loads(response.text)
id_del_upload = datos["data"]["id"]

## PREPARAMOS LA URL PARA HACER LA CONSULTA CON EL ID DEL FICHERO SUBIDO
url_get_analysis = "https://www.virustotal.com/api/v3/analyses/"+str(id_del_upload)

## HACEMOS LA CONSULTA A VT
response = requests.get(url_get_analysis, headers=headers)

## DEVUELVE ALGO SIMILAR A ESTO:
## {
##     "meta": {
##         "file_info": {
##             "sha256": "696d33b1e68c29a9478e950be5bfe779ff4db5c8a57b8074512af8439829b40b",
##             "sha1": "176e9d28bdf2c90e670ddeefeea0e16ebebe464c",
##             "md5": "8ce3b85c663dc65736460587cc103bb3",
##             "size": 17219
##         }
##     },
##     "data": {
##         "attributes": {
##             "date": 1657036044,
##             "status": "queued",
##             "stats": {
##                 "harmless": 0,
##                 "type-unsupported": 0,
##                 "suspicious": 0,
##                 "confirmed-timeout": 0,
##                 "timeout": 0,
##                 "failure": 0,
##                 "malicious": 0,
##                 "undetected": 0
##             },
##             "results": {}
##         },
##         "type": "analysis",
##         "id": "OGNlM2I4NWM2NjNkYzY1NzM2NDYwNTg3Y2MxMDNiYjM6MTY1NzAzNjA0NA==",
##         "links": {
##             "item": "https://www.virustotal.com/api/v3/files/696d33b1e68c29a9478e950be5bfe779ff4db5c8a57b8074512af8439829b40b",
##             "self": "https://www.virustotal.com/api/v3/analyses/OGNlM2I4NWM2NjNkYzY1NzM2NDYwNTg3Y2MxMDNiYjM6MTY1NzAzNjA0NA=="
##         }
##     }
## }

print(response.text)

## AHORA NOS INTERESA RESCATAR EL SHA256 PARA AÑADIRLO A NUESTRA COLECCIÓN Y VOTAR NEGATIVAMENTE
datos=json.loads(response.text)
sha256_del_upload = datos["meta"]["file_info"]["sha256"]

print(sha256_del_upload)

## SUBIMOS EL VOTO. SI QUEREMOS QUE SEA NEGATIVO, EL PARÁMETRO ES "malicious", SI NO "harmless" 
url = "https://www.virustotal.com/api/v3/files/"+sha256_del_upload+"/votes"

payload = {"data": {
        "type": "vote",
        "attributes": {"verdict": "malicious"}
    }
}


response = requests.post(url, json=payload, headers=headers)

print(response.text)

## AÑADIMOS EL FICHERO A UNA COLLECION PROPIA
## wiki -> https://developers.virustotal.com/reference/collectionsid-2

url = "https://www.virustotal.com/api/v3/collections/"+ID_de_la_coleccion

payload = {
    "data": {
        "attributes": {
            "name": "MIS DETECCIONES",
            "description": nueva_descripcion
        },
        "raw_items": sha256_del_upload,
        "type": "collection"
    }
}

response = requests.patch(url, json=payload, headers=headers)

print(response.text)
