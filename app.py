import os
import qrcode
from io import BytesIO
from Crypto.Cipher import AES
import base64
import random
from flask import Flask, render_template, send_file, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


password_of_aes = "Xlmw mw e zivc iewc GXJ uyiwxmsr"
password_of_text = "This is a very easy CTF question"


def aesEncrypt(key, data):
    '''
    AES的ECB模式加密方法
    :param key: 密钥
    :param data:被加密字符串（明文）
    :return:密文
    '''
    key = key.encode('utf8')
    # 字符串补位
    data = pad(data)
    cipher = AES.new(key, AES.MODE_ECB)
    # 加密后得到的是bytes类型的数据，使用Base64进行编码,返回byte字符串
    result = cipher.encrypt(data.encode())
    encodestrs = base64.b64encode(result)
    enctext = encodestrs.decode('utf8')
    print(enctext)
    return enctext

@app.route('/generate_qr_code')
def generate_qr_code():
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    # 生成随机验证码
    random_text = str(random.randint(100000, 999999))
    session['random_text'] = random_text
    enctext = aesEncrypt(password_of_text, str(random_text))
    qrcode_text = "PASSWORD:" + password_of_aes + " TEXT: " +  enctext
    qr.add_data(qrcode_text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_bytes = BytesIO()
    img.save(img_bytes, format='PNG')
    img_bytes.seek(0)
    return send_file(img_bytes, mimetype='image/png')

@app.route('/')
def index():
    session['random_text'] = str(977217)
    return render_template('index.html')

@app.route('/validate', methods=['POST'])
def validate():
    input_text = request.form['input_text']
    if input_text == session.get('random_text'):
        return redirect(url_for('second_page'))
    else:
        return redirect(url_for('index'))


@app.route('/second_page')
def second_page():
    return render_template('second_page.html')
    
if __name__ == '__main__':
    app.run(debug=True)
