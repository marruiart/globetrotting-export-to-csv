import os
import csv
import codecs
from datetime import datetime, timezone
from firebase_functions import https_fn, options
from flask import jsonify

# The Firebase Admin SDK to access Cloud Firestore.
from firebase_admin import initialize_app, firestore, storage, credentials

BUCKET_NAME = "globetrotting-80e83.appspot.com"

cred = credentials.ApplicationDefault()
app = initialize_app(cred, {"storageBucket": "globetrotting-80e83.appspot.com"})
db = firestore.client()
bucket = storage.bucket()

USERS_HEADER = ["ID", "EMAIL", "NOMBRE_COMPLETO", "NICKNAME", "ROL", "CREACION"]
BOOKINGS_HEADER = [
    "ID",
    "INGRESO",
    "CLIENTE",
    "ID_CLIENTE",
    "DESTINO",
    "ID_DESTINO",
    "NUM_NOCHES",
    "VIAJEROS",
    "CREACION",
]
DESTINATION_HEADER = [
    "ID",
    "NOMBRE",
    "COORDENADAS",
    "DIMENSION",
    "TIPO",
    "PRECIO",
    "CREACION",
]


class BadRequestException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.error_code = "BAD_REQUEST"
        self.status_code = 400
        self.message = message


class InternalServerError(Exception):
    def __init__(self, message="Ups! There was an unexpected error."):
        super().__init__(message)
        self.error_code = "INTERNAL_SERVER_ERROR"
        self.status_code = 500
        self.message = message


def get_header(collection):
    if collection == "users":
        return USERS_HEADER
    elif collection == "bookings":
        return BOOKINGS_HEADER
    elif collection == "destinations":
        return DESTINATION_HEADER


def map_data(collection, doc):
    if collection == "users":
        return map_user(doc)
    elif collection == "bookings":
        return map_booking(doc)
    elif collection == "destinations":
        return map_destination(doc)


def format_date(date, date_format="%Y%m%d%H%M%S"):
    return date.strftime(date_format)


def get_file_name(collection, date, extension):
    formatted_date = format_date(date)
    return f"{collection}_{formatted_date}{extension}"


def fetch_documents(processed_documents, collection):
    collection_ref = db.collection(collection)
    docs = collection_ref.stream()
    processed_documents = proccess_documents(collection, docs, processed_documents)


def proccess_documents(collection, documents, processed_documents):
    for doc in documents:
        mapped_data = map_data(collection, doc.to_dict())
        processed_documents.append(mapped_data)
    return processed_documents


def map_user(user):
    name = user.get("name", "")
    surname = user.get("surname", "")
    full_name = ""
    if name and surname:
        full_name = f"{name} {surname}"
    elif name:
        full_name = f"{name}"
    return {
        "ID": user.get("user_id", ""),
        "EMAIL": user.get("email", ""),
        "NOMBRE_COMPLETO": full_name,
        "NICKNAME": user.get("nickname", ""),
        "ROL": user.get("role", ""),
        "CREACION": user.get("createdAt", None),
    }


def map_booking(booking):
    return {
        "ID": booking.get("id", ""),
        "INGRESO": booking.get("amount", ""),
        "CLIENTE": booking.get("clientName", ""),
        "ID_CLIENTE": booking.get("client_id", ""),
        "DESTINO": booking.get("destinationName", ""),
        "ID_DESTINO": booking.get("destination_id", ""),
        "NUM_NOCHES": booking.get("nights", ""),
        "VIAJEROS": booking.get("travelers", ""),
        "CREACION": booking.get("createdAt", None),
    }


def map_destination(destination):
    lat = destination.get("coordinate", {}).get("lat", None)
    lng = destination.get("coordinate", {}).get("lng", None)
    coordinate = None
    if lat and lng:
        coordinate = f"{lat}; {lng}"
    return {
        "ID": destination.get("id", ""),
        "NOMBRE": destination.get("name", ""),
        "COORDENADAS": coordinate,
        "DIMENSION": destination.get("dimension", ""),
        "TIPO": destination.get("type", ""),
        "PRECIO": destination.get("price", ""),
        "CREACION": destination.get("createdAt", ""),
    }


def write_to_csv_file(collection, tmp_file_path, proccessed_documents):
    print("Writing to csv file...")
    try:
        with codecs.open(tmp_file_path, "w", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=get_header(collection),
                delimiter=";",
                lineterminator="\n",
            )
            writer.writeheader()
            if proccessed_documents:
                for doc in proccessed_documents:
                    writer.writerow(doc)
    except IOError as ex:
        print(f"IO error: {ex}")
    except csv.Error as ex:
        print(f"CSV error: {ex}")
    except (TypeError, ValueError) as ex:
        print(f"Data format error: {ex}")


def upload_file_to_bucket(file_name, user_id) -> str:
    try:
        print(f"Uploading {file_name} to bucket...")
        blob = bucket.blob(f"csv_files/{user_id}/{file_name}")
        blob.upload_from_filename(file_name)
        print(f"{file_name} file uploaded successfully!")
        return blob.public_url
    except FileNotFoundError as ex:
        print(f"File not found: {ex}")
        raise InternalServerError("File not found") from ex
    except Exception as ex:
        print(f"An error occurred: {ex}")
        raise InternalServerError() from ex


def get_body_data(req):
    body_data = req.get_json(silent=True)
    if body_data is None:
        raise BadRequestException("'user_id' and 'request' fields are required.")

    if "user_id" not in body_data:
        raise BadRequestException("'user_id' field is required.")

    if "collection" not in body_data or body_data["collection"] not in (
        "users",
        "bookings",
        "destinations",
        "all",
    ):
        raise BadRequestException(
            "'collection' field is required or incorrect payload."
        )
    return body_data


def get_response(status_code=200, error_code="", message="", response=""):
    if status_code == 200:
        return https_fn.Response(
            status=status_code,
            response=jsonify(response).data,
        )
    return https_fn.Response(
        status=status_code,
        response=jsonify(
            {
                "error_code": error_code,
                "message": message,
            }
        ).data,
    )


@https_fn.on_request(cors=options.CorsOptions(cors_origins="*", cors_methods=["post"]))
def export_firestore_data(req: https_fn.Request) -> https_fn.Response:
    """Get the server's local date and time."""
    try:
        if req.method != "POST":
            return https_fn.Response(
                status=403,
                response=jsonify(
                    {
                        "error_code": "FORBIDDEN",
                        "message": f"{req.method} is not allowed.",
                    }
                ).data,
            )

        body_data = get_body_data(req)
        user_id = body_data["user_id"]
        collection = body_data["collection"]

        # Obtén la fecha y hora actual para usarla como parte del nombre del archivo CSV
        current_date = datetime.now(timezone.utc)
        file_name = get_file_name(collection, current_date, ".csv")
        if collection != "all":
            collection_name = collection
            processed_documents = []
            fetch_documents(processed_documents, collection_name)
            write_to_csv_file(collection, file_name, processed_documents)
            # URL del archivo recién cargado
            file_url = upload_file_to_bucket(file_name, user_id)
            return get_response(response={"files_location": [file_url]})
        else:
            file_url = []
            for collection_name in ("users", "destinations", "bookings"):
                processed_documents = []
                fetch_documents(processed_documents, collection_name)
                write_to_csv_file(
                    collection, file_name, processed_documents
                )
                # URL del archivo recién cargado
                file_url.append(upload_file_to_bucket(file_name, user_id))
            return get_response(response={"files_location": file_url})
        # Consulta todos los documentos en la colección de Firestore

    except BadRequestException as ex:
        return get_response(ex.status_code, ex.error_code, ex.message)
    except InternalServerError as ex:
        return get_response(ex.status_code, ex.error_code, ex.message)
    except Exception as ex:
        print(ex)
        return get_response(
            500, "INTERNAL_SERVER_ERROR", "Ups! There was an unexpected error."
        )
