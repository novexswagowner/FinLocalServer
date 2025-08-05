from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

params = dh.generate_parameters(generator=2, key_size=2048)
with open("dh_params.pem", "wb") as f:
    f.write(params.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    ))
