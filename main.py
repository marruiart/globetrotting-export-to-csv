from datetime import datetime, timezone
import traceback
import pandas as pd
from flask import jsonify

# The Firebase Admin SDK to access Cloud Firestore.
from firebase_admin import initialize_app, firestore, storage, credentials, auth
import functions_framework

BUCKET_NAME = "globetrotting-80e83.appspot.com"

cred = credentials.ApplicationDefault()
app = initialize_app(cred, {"storageBucket": "globetrotting-80e83.appspot.com"})
db = firestore.client()
bucket = storage.bucket()

USERS_HEADER = [
    "ID",
    "EMAIL",
    "NOMBRE_COMPLETO",
    "GENERO",
    "NICKNAME",
    "FAVORITOS",
    "ROL",
    "FECHA_CREACION",
    "FECHA_ACTUALIZACION",
]

BOOKINGS_HEADER = [
    "ID",
    "INGRESO",
    "ID_CLIENTE",
    "ID_AGENTE",
    "ID_DESTINO",
    "CONFIRMADA",
    "NUM_NOCHES",
    "VIAJEROS",
    "SALIDA",
    "LLEGADA",
    "FECHA_CREACION",
    "FECHA_ACTUALIZACION",
]

DESTINATION_HEADER = [
    "ID",
    "NOMBRE",
    "COORDENADAS",
    "PAIS",
    "UNION_POLITICA",
    "CONTINENTE",
    "KEYWORDS",
    "TIPO",
    "PRECIO",
    "FECHA_CREACION",
    "FECHA_ACTUALIZACION",
]


class BadRequestException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.error_code = "BAD_REQUEST"
        self.status_code = 400
        self.message = message


class UnauthorizedException(Exception):
    def __init__(self, message="Unauthorized"):
        super().__init__(message)
        self.error_code = "UNAUTHORIZED"
        self.status_code = 401
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
    return f"{formatted_date}{extension}"


def fetch_documents(processed_documents, collection):
    collection_ref = db.collection(collection)
    docs = collection_ref.stream()
    processed_documents = process_documents(collection, docs, processed_documents)


def verify_id_token(token: str):
    try:
        return auth.verify_id_token(token)
    except auth.ExpiredIdTokenError as ex:
        raise UnauthorizedException("The token has expired") from ex
    except auth.RevokedIdTokenError as ex:
        raise UnauthorizedException("The token has been revoked") from ex
    except auth.InvalidIdTokenError as ex:
        raise UnauthorizedException("The token is invalid") from ex
    except auth.CertificateFetchError as ex:
        raise UnauthorizedException(
            "Error fetching public keys to verify token"
        ) from ex
    except Exception as ex:
        raise UnauthorizedException(f"Token verification failed: {str(ex)}") from ex


def check_user_permission(user_id: str):
    not_authorized = "The current user is not authorized to access this resource"
    if not user_id:
        raise UnauthorizedException(not_authorized)

    collection_ref = db.collection("users")
    user_doc = collection_ref.document(user_id).get()

    if user_doc.exists:
        user_data = user_doc.to_dict()
        role = user_data["role"]
        if role == "AUTHENTICATED":
            raise UnauthorizedException(not_authorized)
    else:
        raise UnauthorizedException(not_authorized)


def process_documents(collection, documents, processed_documents):
    for doc in documents:
        doc_dict = doc.to_dict()
        print(doc_dict)
        mapped_data = map_data(collection, doc_dict)
        processed_documents.append(mapped_data)
    return processed_documents


def get_favorites(user):
    favorites = []
    if user.get("role") == "AUTHENTICATED":
        for fav in user.get("favorites") or []:
            favorites.append(fav["destination_id"])
    return favorites


def map_user(user):
    name = user.get("name", "")
    surname = user.get("surname", "")
    full_name = ""
    if name and surname:
        full_name = f"{name} {surname}"
    elif name:
        full_name = f"{name}"
    return {
        "ID": user.get("user_id"),
        "EMAIL": user.get("email"),
        "NOMBRE_COMPLETO": full_name,
        "GENERO": user.get("gender", "unknown"),
        "NICKNAME": user.get("nickname", ""),
        "FAVORITOS": "|".join(get_favorites(user)),
        "ROL": user.get("role"),
        "FECHA_CREACION": user.get("createdAt"),
        "FECHA_ACTUALIZACION": user.get("updatedAt"),
    }


def map_booking(booking):
    return {
        "ID": booking.get("id"),
        "INGRESO": booking.get("amount", 0),
        "ID_CLIENTE": booking.get("client_id"),
        "ID_AGENTE": booking.get("agent_id"),
        "ID_DESTINO": booking.get("destination_id"),
        "CONFIRMADA": booking.get("isConfirmed", False),
        "NUM_NOCHES": booking.get("nights", ""),
        "VIAJEROS": booking.get("travelers", ""),
        "SALIDA": booking.get("start"),
        "LLEGADA": booking.get("end"),
        "FECHA_CREACION": booking.get("createdAt"),
        "FECHA_ACTUALIZACION": booking.get("updatedAt"),
    }


def map_destination(destination):
    lat = destination.get("coordinate", {}).get("lat")
    lng = destination.get("coordinate", {}).get("lng")
    coordinate = None
    if lat and lng:
        coordinate = f"{lat}; {lng}"
    return {
        "ID": destination.get("id"),
        "NOMBRE": destination.get("name"),
        "COORDENADAS": coordinate,
        "KEYWORDS": "|".join(destination.get("keywords") or []),
        "PAIS": destination.get("country"),
        "UNION_POLITICA": destination.get("policitalUnion"),
        "CONTINENTE": destination.get("continent"),
        "TIPO": destination.get("type"),
        "PRECIO": destination.get("price"),
        "FECHA_CREACION": destination.get("createdAt"),
        "FECHA_ACTUALIZACION": destination.get("updatedAt"),
    }


def write_to_csv_file(collection, tmp_file_path, processed_documents):
    print("Writing to csv file...")
    try:
        headers = get_header(collection)
        df = pd.DataFrame(processed_documents, columns=headers)

        if "INGRESO" in df.columns:
            df["INGRESO"] = pd.to_numeric(df["INGRESO"], errors="coerce")
            df["INGRESO"] = df["INGRESO"].apply(
                lambda x: f"{x:.2f}".replace(".", ",") if pd.notnull(x) else x
            )

        if "PRECIO" in df.columns:
            df["PRECIO"] = pd.to_numeric(df["PRECIO"], errors="coerce")
            df["PRECIO"] = df["PRECIO"].apply(
                lambda x: f"{x:.2f}".replace(".", ",") if pd.notnull(x) else x
            )

        df.to_csv(tmp_file_path, sep=";", index=False, encoding="utf-8")
    except IOError as ex:
        print(f"IO error: {ex}")
        raise
    except (TypeError, ValueError) as ex:
        print(f"Data format error: {ex}")
        raise
    except Exception as ex:
        print(f"Unexpected error at writing to csv file: {ex}")
        raise


def upload_file_to_bucket(file_name, collection) -> str:
    try:
        print(f"Uploading {file_name} to bucket...")
        blob = bucket.blob(f"{collection}/{file_name}")
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

    if (
        body_data is None
        or "collection" not in body_data
        or body_data["collection"]
        not in (
            "users",
            "bookings",
            "destinations",
            "all",
        )
    ):
        raise BadRequestException(
            "'collection' field is required or incorrect payload."
        )
    return body_data


def get_response(headers, status_code=200, error_code="", message=""):
    if status_code == 204:
        return (message, status_code, headers)
    if status_code == 200:
        return (jsonify(message).data, status_code, headers)
    return (
        jsonify(
            {
                "error_code": error_code,
                "message": message,
            }
        ).data,
        status_code,
        headers,
    )


@functions_framework.http
def export_firestore_data(request):
    """Export the firestore data to a CSV file."""
    print(request)
    try:
        # Set CORS headers for the preflight request
        if request.method == "OPTIONS":
            headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST",
                "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
                "Access-Control-Max-Age": "3600",
            }
            return get_response(headers, 204)

        # Set CORS headers for the main request
        headers = {"Access-Control-Allow-Origin": "*"}

        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            raise UnauthorizedException()
        token = auth_header.split("Bearer ")[1]
        decoded_token = verify_id_token(token)
        check_user_permission(user_id=decoded_token.get("user_id"))
        body_data = get_body_data(request)

        if request.method != "POST":
            return get_response(
                headers, 403, "FORBIDDEN", f"{request.method} is not allowed."
            )

        collection = body_data["collection"]
        # Get the current date and time to use it as part of the CSV file name
        current_date = datetime.now(timezone.utc)
        file_name = get_file_name(collection, current_date, ".csv")
        if collection != "all":
            collection_name = collection
            processed_documents = []
            fetch_documents(processed_documents, collection_name)
            write_to_csv_file(collection, file_name, processed_documents)
            # URL of the newly uploaded file
            file_url = upload_file_to_bucket(file_name, collection_name)
            return get_response(headers, message={"files_location": [file_url]})
        else:
            file_url = []
            for collection_name in ("users", "destinations", "bookings"):
                processed_documents = []
                fetch_documents(processed_documents, collection_name)
                write_to_csv_file(collection, file_name, processed_documents)
                # URL of the newly uploaded file
                file_url.append(upload_file_to_bucket(file_name, collection_name))
            return get_response(headers, message={"files_location": file_url})

    except UnauthorizedException as ex:
        print(ex)
        return get_response(headers, ex.status_code, ex.error_code, ex.message)
    except BadRequestException as ex:
        print(ex)
        return get_response(headers, ex.status_code, ex.error_code, ex.message)
    except InternalServerError as ex:
        print(ex)
        return get_response(headers, ex.status_code, ex.error_code, ex.message)
    except Exception as ex:
        print(ex)
        print(traceback.print_exc())
        return get_response(
            headers, 500, "INTERNAL_SERVER_ERROR", "Ups! There was an unexpected error."
        )
