import io
import tempfile

import flask
import os
from urllib.parse import urlparse

from apiclient.http import MediaIoBaseDownload, MediaIoBaseUpload
import googleapiclient.discovery
from googleapiclient.errors import HttpError
import urllib
import requests
from google_auth import build_credentials, get_user_info
import gdown
from werkzeug.utils import secure_filename

app = flask.Blueprint('google_drive', __name__)

from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import scrypt
import google_auth
import os


def encrypt(filename,user_password,file_in):

    BUFFER_SIZE = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once

    password = user_password  # Get this from somewhere else like input()

    input_filename = filename  # Any file extension will work
    # output_filename = input_filename + '.encrypted'  # You can name this anything, I'm just putting .encrypted on the end

    file_out = tempfile.TemporaryFile()

    # Open files
    #file_in = file_in  # rb = read bytes. Required to read non-text files
    #file_out = open(output_filename, 'wb')  # wb = write bytes. Required to write the encrypted data

    salt = get_random_bytes(32)  # Generate salt
    key = scrypt(password, salt, key_len=32, N=2 ** 17, r=8, p=1)  # Generate a key using the password and salt
    file_out.write(salt)  # Write the salt to the top of the output file

    cipher = AES.new(key, AES.MODE_GCM)  # Create a cipher object to encrypt data
    file_out.write(cipher.nonce)  # Write out the nonce to the output file under the salt

    # Read, encrypt and write the data
    data = file_in.read(BUFFER_SIZE)  # Read in some of the file
    while len(data) != 0:  # Check if we need to encrypt anymore data
        encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
        file_out.write(encrypted_data)  # Write the encrypted data to the output file
        data = file_in.read(BUFFER_SIZE)  # Read some more of the file to see if there is any more left

    # Get and write the tag for decryption verification
    tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
    file_out.write(tag)
    # print(tag, "Encrypt tag")
    # Close both files
    file_in.close()
    # file_out.close()

    return file_out

def decrypt(filename,user_password,file_in,key=None):

    BUFFER_SIZE = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once
    # print(file_in.read())
    # file_in.seek(0)
    password = user_password  # Get this from somewhere else like input()

    output_filename = filename  # The decrypted file
    file_in.seek(0, os.SEEK_END)
    file_size = file_in.tell()
    file_in.seek(0)
    # Open files
    file_in = file_in
    file_out = tempfile.TemporaryFile()
    salt = file_in.read(32)  # The salt we generated was 32 bits long

    # Read salt and generate key
    if not key:
        key = scrypt(password, salt, key_len=32, N=2 ** 17, r=8, p=1)  # Generate a key using the password and salt again
    # Read nonce and create cipher
    nonce = file_in.read(16)  # The nonce is 16 bytes long
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Identify how many bytes of encrypted there is
    # We know that the salt (32) + the nonce (16) + the data (?) + the tag (16) is in the file
    # So some basic algebra can tell us how much data we need to read to decrypt
    file_in_size = file_size
    encrypted_data_size = file_in_size - 32 - 16 - 16  # Total - salt - nonce - tag = encrypted data
    # Read, decrypt and write the data
    for _ in range(
            int(encrypted_data_size / BUFFER_SIZE)):  # Identify how many loops of full buffer reads we need to do
        data = file_in.read(BUFFER_SIZE)  # Read in some data from the encrypted file
        decrypted_data = cipher.decrypt(data)  # Decrypt the data
        file_out.write(decrypted_data)  # Write the decrypted data to the output file
    data = file_in.read(
        int(encrypted_data_size % BUFFER_SIZE))  # Read whatever we have calculated to be left of encrypted data
    decrypted_data = cipher.decrypt(data)  # Decrypt the data
    file_out.write(decrypted_data)  # Write the decrypted data to the output file

    # Verify encrypted file was not tampered with
    tag = file_in.read(16)
    try:
        cipher.verify(tag)
    except ValueError as e:
        # If we get a ValueError, there was an error when decrypting so delete the file we created
        file_in.close()
        file_out.close()
        try:
            os.remove(output_filename)
        except Exception as error:
            pass

        raise e

    # If everything was ok, close the files
    file_in.close()
    # file_out.close()
    return file_out,key

def build_drive_api_v3():
    credentials = build_credentials()
    return googleapiclient.discovery.build('drive', 'v3', credentials=credentials).files()

def build_drive_service_v3():
    credentials = build_credentials()
    return googleapiclient.discovery.build('drive', 'v3', credentials=credentials)


def set_permission(file_id):
    service = build_drive_service_v3()
    try:
        permission = {'type': 'anyone',
                      'value': 'anyone',
                      'role': 'reader'}
        return service.permissions().create(fileId=file_id,body=permission).execute()
    except HttpError as error:
        return print('Error while setting permission:', error)

def save_image(file_name, mime_type, file_data,file_id=None):
    drive_api = build_drive_api_v3()
    generate_ids_result = drive_api.generateIds(count=1).execute()
    new_file_id = generate_ids_result['ids'][0]

    if not file_id:


        body = {
            'id': new_file_id,
            'name': file_name,
            'mimeType': mime_type,
            "role": "reader",
            "type": "anyone",
            'value': '',

        }
    else:
        body = {
            'name': file_name,
            'mimeType': mime_type,
            "role": "reader",
            "type": "anyone",
            'value': '',

        }


    media_body = MediaIoBaseUpload(file_data,
                                   mimetype=mime_type,
                                   resumable=True)
    if not file_id:
        drive_api.create(body=body,
                         media_body=media_body,
                         fields='id,name,mimeType,createdTime,modifiedTime').execute()
        file_id = new_file_id
    else:
        drive_api.update(fileId =file_id,body=body,
                         media_body=media_body,
                         fields='id,name,mimeType,createdTime,modifiedTime').execute()
    set_permission(file_id)
    return file_id

@app.route('/gdrive/upload', methods=['GET', 'POST'])
def upload_file():
    if 'file' not in flask.request.files:
        return flask.redirect('/')

    file = flask.request.files['file']
    if (not file):
        return flask.redirect('/')
    password = flask.request.form.get('password')
    filename = secure_filename(file.filename)
    file_out = encrypt(filename,password,file)
    file_out.seek(0)
    # fp = tempfile.TemporaryFile()
    # ch = file.read()
    # fp.write(ch)
    # fp.seek(0)

    # Encrypt the File here
    #print(file_out.close())

    mime_type = flask.request.headers['Content-Type']
    save_image(filename, mime_type, file_out,file_id=None)

    return flask.redirect('/')

@app.route('/gdrive/view/<file_id>', methods=['GET','POST'])
def access_file(file_id):

    # get password
    if flask.request.method == 'GET':
        return flask.render_template('edit.html', file_content='',
                                     user_info=google_auth.get_user_info(),file_id=file_id)



    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType,webViewLink", fileId=file_id).execute()

    request = drive_api.get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, request)

    done = False
    while done is False:
        status, done = downloader.next_chunk()

    fh.seek(0)
    file_name = metadata['name']
    password = flask.request.form.get("password")
    try:
        file_out,key = decrypt(file_name,password,fh,key=None)
        file_out.seek(0)
    except ValueError as e:
        return flask.render_template('edit.html', file_content="File Was modified - Decryption Error / Wrong password",
                                     user_info=google_auth.get_user_info(), file_name=file_name)

    if flask.request.form.get("share", None):
        # generate key with password and file url
        share_url = metadata['webViewLink']
        return flask.render_template('edit.html', share_url=share_url,
                                     user_info=google_auth.get_user_info(), share=True, key=key.hex())

    # return flask.send_file(
    #                  fh,
    #                  attachment_filename=metadata['name'],
    #                  mimetype=metadata['mimeType']
    #            )
    return  flask.render_template('edit.html', file_content=file_out.read().decode("utf-8") ,
                                  user_info=google_auth.get_user_info(), file_name = file_name,
                                  file_id=file_id,password = password)

@app.route('/gdrive/delete/<file_id>', methods=['GET'])
def delete_file(file_id):
    drive_api = build_drive_api_v3()
    drive_api.delete(fileId=file_id).execute()

    return flask.redirect('/')

@app.route('/gdrive/save/<file_id>', methods=['POST'])
def update_file(file_id):


    drive_api = build_drive_api_v3()

    metadata = drive_api.get(fields="name,mimeType", fileId=file_id).execute()

    # request = drive_api.get_media(fileId=file_id)

    file_name = metadata['name']
    password = flask.request.form.get("password")
    content = flask.request.form.get("content")
    file_out = tempfile.TemporaryFile()
    file_out.write(content.encode('utf-8'))
    file_out.seek(0)
    file_out = encrypt(file_name, password, file_out)
    file_out.seek(0)
    mime_type = flask.request.headers['Content-Type']
    print(file_id)
    save_image(file_name, mime_type, file_out,file_id=file_id)

    return flask.redirect('/')

def download_file_from_google_drive(url, destination):
        gdown.download(url, destination, quiet=False)

        return destination

@app.route('/gdrive/view-shared-file', methods=['GET','POST'])
def view_shared_file():


    # get password
    if flask.request.method == 'GET':
        return flask.render_template('view.html', file_content='',
                                     view_share=True)

    secretKey = flask.request.form.get("secretKey")
    fileUrl = flask.request.form.get("fileUrl")
    print(fileUrl)
    a = urlparse(fileUrl)
    file_out = tempfile.TemporaryFile()
    file_name = os.path.basename(a.path)
    # file = requests.get(fileUrl, allow_redirects=True)
    fileUrl =  "https://drive.google.com/uc?id={}".format(fileUrl.split("/")[5])
    download_file_from_google_drive(fileUrl, file_out)
    # print(file.content)
    # file_out.write(file.content)
    file_out.seek(0)
    # print(file_out.read())


    try:
        file_out,key = decrypt(file_name,'',file_out,key=bytes.fromhex(secretKey))
        file_out.seek(0)
        return {"response": file_out.read().decode("utf-8")}
    except ValueError as e:
        print(str(e))
        return {"response":"Error - Corrupted Data"}

