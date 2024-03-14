import sys
from pathlib import Path
from shutil import which
from typing import List
from typing import Union

import pytest

archive_files = [
    "archive_aes.7z.p7b",
    "archive_aes_truncated.7z.p7b",
    "archive_aes_padded.7z.p7b",
    "archive_aes_corrupted.7z.p7b",
    "archive_des.7z.p7b",
    "archive_des_truncated.7z.p7b",
    "archive_des_padded.7z.p7b",
    "archive_des_corrupted.7z.p7b",
]
methods = ["python", "openssl"]
recipient1_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCjNBlJOHc8/SBX
bdGFj1Q0bBhsMzkzqP7lf7mAZovQRPaT1gwe69UU+1K800jAPqH4Rt9oNG3jC/cm
2+DLaNa41nnc6D2lRnL0+sVO6lbecmY9Rw9Sh6jMEnU4fzBAcCRc4KZkvmpIQsTH
ZHjivjHVHWeIeQJiSpEjolKDNJZL5SArmFokwq8RvGKa6kesOFX8f9jaa0ISfW3h
Dhx1QRWkYH2DV/2fqMNbU/2DPTECF+zxYCxfYFHT0WdDFCDu9QIh9mYSgB018sGi
ZDrwndSq9sHX2clCEJ3NnAnIGEe6JnQ/rEEZXT9wVlVRePD+EwQVJe1iOLEUTmN2
yjg1ZtpJAgMBAAECggEBAKFeQiJD0qJbJj9MNn742Sl8OCnD/Cs4TdBeGez7eALW
LXi/i/yG8olsdsJ9ptFvHHeAnCVMsdptWlLx1bNKVgUtDBGBEHL61W+lBLKiwoHw
W2b7fAr+V8hv97eFCxCr0UiEWAIExNHuMuN0VJLdvCgciuJFxDWrxRaWyT8yH+mp
b2g4TPGZ7xH77lHSZP367gzlb2EiNKCW3QtZbmx3nZwccEwnWDvWbFXFVI2IqNnN
FQMSbjVU775uug+JzecvR2iaavQCt+KkWHloK3iemfzPY6sOZHTruzHwmO2ZoJ1t
a7Ju8Xrl8X0RtR+66XyMPxCgINBNqw6pUo0e3f7cFoECgYEA0hgHhegncvN1xI+f
a5oUoh+Xbo6xv2IDYVv13+pqWxobdFqpqDCITkbE+7HZ1lO/h7JWz9rz7ghG/kcc
ViErGCtr6L5MfKVBVQM8WpAlMNTLAV6tHlbEkMeqTnBepK3Aal8RXjyNfBiq0qgN
PHo2R9sXUNFvovbxTodBfdhywXcCgYEAxt0sv1afJrTMXkYzgh8pN7AUC3R9H0/5
HC/s5iyh2Gx1R3Ms3NErrSmZ1qJe969FHwT7AfhWf8ijmOd5ANgqkT+auG+1CLbC
ov23Fz1pxn5mB4sOA0YApBqhaY5kP1atjl2nw/oswlG3MhBDV0BEq2zhiYmmDiET
X9Bds4ugMj8CgYAsUolzxJBd/eLAfxRA3RaxRTzrRAtXttPDvGTYwlmBsrZMC7xz
ERoQeXmhJ9ovDyf+9q691xFTDEf96P6fZQv0Y2S2iz8TpMFtr+sRqAtQi/Pv7AtV
tTRu3tCdD7PHxigryLafTOMEZSfUnUN9mMLO0ffPQv/sP3CVAo/cfsdm7QKBgQCn
+60Q89r8lz0LZcGc6TWoFNTZ2EzZZnTHmrRCuvD8IKHw+RmsbgS3Aa0x4XbXQvbg
fRSLVXu79YA8aUuNqwxKJbBMnBAQjFFd3XQL7ZSsV5lYRd5QZZGlDdnLkLydxFpX
KEXPBkVI4D4fzB0WVvOq2w6pX90lkksLZLfCMu/fgQKBgBtsEdRwQRgta44GtIIo
GuIZoIa+5INk1dj3stisQwoKqGHRUAAJACY/c/T0OwTlJjwKTMGb5b4J1au4Ntkg
mZSjym3ezKto7vGYGm6xaPugTO1EaXZ1gCUH2S4mM408H8sW2pwHj5Wpm+FpT6gM
EVPx2hANX64KC7SeRyAv07G6
-----END PRIVATE KEY-----
"""
recipient1_enc_key = b"""-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIc0EFr17/xiICAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBD7iRy82th8uUHSaEOgqEZNBIIE
0E3FPOVwJs1cjkj6gmzVMxLSDWlrkz7ndR3YFCTg2ktLuefvav1nRu5rDhq3YPJP
MzofybExvOTq3oXLtXh9P4yeMtpN7KcklvHJ+8UG1xEHSncTmFGyq8/U1B2spfx+
m3lKTqE4L79j6H1PG4i9WL+KFauqL7xMPd1fKux7U3zMeqMLV8VaRIGbxThl9cJW
cQH4draXLezclhdFQRVU14Ga+T4eULfjge/B6iUWDkpyAFw2ymJQ6jspdq7Zq1FC
TrCDBHVQqu1Bt/7JWgCxZMDn1LDPsBwf4XPGCSpZ+kbU9uLPKUdT9qGqYWIVTVnb
sDpsGqOjbYBCpRqUCfMPKXGF683A8QLDFCdQhcdTubk/wUUjDP1aHg8on3lHokJ1
29/Zs7zqocNCqTwHVbVXY2Bk3EOtrOy5nDnhqAo6+0sittION/F4dgI1DOZXYp5J
k6016Mn6XAUNhrvH1tVhXb9UWsdvNof7Sk/9e+H4Nhk1d0j8Hm3SBVL6SL29z8oX
aK51E3VzepaMmQ8cq7nHFXezXvWV6DR2hEd68W2o0h0FJBDIHQ6jenfPIc6/yi2K
TEY0plEjQaAVYuklaEjS5I37f3w4hOpvWNOQ0MlepZT2c4iWkk1hN3S00XVOW0As
FexG9Dp0RmYgyQPoQT8ifv/GxJNE8iPiksDjolah7+iZhKupxVMtcjNhK1LcqfrD
Lp+T+QZ+RqilfvqtyKGGDG/mm/E4CtgBC4Es/99hm6t9FHJbqX3Sd+vvCKrKMTZS
vY6q0s9kCIegMz4n9E1RY4vacDx/hRYK5/naDF4q8cCT46bYf50wwWdOFk/TphC2
vVNVnngGHFM/r+2SrMYGZoZcfVqow5GxZ3SIHkrWgs77uj15W09WTS93fZIv53VX
LzkqmKMN9mBUx47uVGFqBBee9ObYXpIJaW4/C3kD6gj7LkVtMYypqf+9OSlG4WxD
MdfSBrW2DxpxpeAjXOvWEPGDrUZv9ky31AFXjL91MuQeopBVU82MCpnPRDuqTGEP
pURWl8zEyyF9ioMIrY28ph4rFGiC3YJC0Qf4VIBxTPDkdPSltExjEgrVYSX0qtg8
ApBe/oKHUipQKQl9R8/Xc4FzUfeghfJA9YC3sxIu0MyG+V6pLwJqGvjp8n8miIC4
flTaCdiLzQHcSsbi2LK1MLNFF+qx+8Efc3ih6czRNF6wuEuXZ1QM9kDv3+iHegFe
XPW2p9tkDinSUiOphZhhlIZRXYCBMESblj8f0DCrIBOY1dHWLvhn77CPxD08jXpj
5n9iutoE9UWL044GRQHvKdsYSvuOrQLZ1ddL3NQIx/z7qRKH0OcNzClH4GtQpFCQ
dhTXu1P4DzVc6j/vB8ltmnrZcJrH6wE8uvTdYtvq8HjGe6GXZngS5qJLXGhvNbvn
wt7TAhvMDBJiwcsjWWgw1iOKcF//FGL5R/hggKoHUwqdAjCoFfon1ffzRJKiGLO5
GXGL4popLZBV1H0fNvuUQBwiv5kjxjQ2gfWWz3XsUSkxq543ZJS75s0JCHddciBc
em6iljmYewsL2NurEsaVGQyii8AVpGQPgdZ/ic3+Fd4RoJekrUhq74CLTQPMqWiF
q/gDpi4/PbRsbcyOLFaB4I6YqaazxJjSTMbUreoheVLq
-----END ENCRYPTED PRIVATE KEY-----
"""
recipient3_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDwfOkQ8kxK6ybk
Gglmuq0nKEdy66VfKdJlBMUS0oasZFlAtHeRgEX2dvswopgaeW5VJsLa45WmrQPB
i/nKJ4BfQZQDYObu5JxqV6YpjkgYNxjJ6PTE44lsJqe71vEFQWTtrwXcMWJ0uiVX
pLof9aZiD31gZcuZh+Xd9ZTvnp+bi6NOeIqbtPBJJeUn0KnF5qnD0OTJIvPkPsGH
oXjhQlOCOvGDQGT8XmDigIVxxnjAdl8qhqWuCNiFH8WNAv43fAaha9+Gs8w8N4Cb
iROceD4bC9XNt6IAzTM69JXEgydks/uBLElwspWy0NN5HTf5B4bVraom3WzMqyZq
OdpBcqCzAgMBAAECggEBAL4rCGJON+ZGbUqTDDwgAiykvVsy3GKUP7uCOhTYRYat
E6cHDkYQmUJ8c8XRzVWiEI1lSVCuBvj2d7HlbnFdKzYoNVM2nWbrgITXKp5R1NDR
QNjpTiUjiNfs+VagcZcmTxlk/c1Rf/mt+TmFGWmMZzXD6fEAji+qNyt9t3iEhtIH
4VoAv+5FWsz6ywk4Z5evzUM5Mtwuthjq6c9aVZmgSdPt9I+F47ekgfOqMNukEXCq
1iS1l4Gpo/m6ujIC3+D76tPmEzatXcXZrm5K9K4liNBlJkHpsI7k/R4IJHxxzcAT
0KWlXpEe9d1+YcoEcWk/rKE0GEo5Wt6/fUGBhZt+kQECgYEA/xzuSCq0/CjjbS+8
dqPtPdpe/jHJYxzhJaR+UfMnTGKo6BaUL4x8ohY+qomFwX3jdpbNipHCpyi2lSh5
EiRs+fycWwwDKF2+hvIiRkquR8xdzVxvln9DbFw4evjkYiVLtNtgqdVXsj+bt7Sw
r9XslevSgWnFv2rYnV0szG1+7FkCgYEA8VL2VS2OLMioyBetNfpC5rhUyQFAV3B/
0YCjFozIQmFKYzkClHOOUGwWrb+ahBmSeswY6sh9VSXhx5sq6SGLFCc3fqWGaZpi
ljGxjlx8ybOKbv9Pio3/o+u/9wxR+bgCeRr6J8FODM3DOFZLhFrSHoNrv919Sxlz
3nwaiL6ro+sCgYEAgOu+4wtqANAs9j2ccRwwRQS44p6IViT/BoXVLFbDsk9dakQW
yNynE0ZIjugGhxy2OXTGFFPK2ayycDhOzsNHqyFkZoJwihKtuQZeGcWdwzzc3m3r
GlPf37/O7x4eVBbi5lfCxrDAq5yHddPDQmjKMY1GCQ5J140IQKYYgIqJDKkCgYBh
kZpYy+dcwfBDnhcA6OMdp09YSXI7KBf1m13U4yygcfeCcG1TmfjjGSB+NSaC3Ff1
4Aj++/p4b61+Z4UM5uv1RPnR8ZiLn8jWUtcn6MrnPfjtcbo2Gb1PCCT//HI0Vapi
Tn7vjd9Bm/ufDnzP0Wx8u8PXufRLZcoMHP8ZZIW+6wKBgQCwFP4IFu+p2GuZ7ZPk
4ScSvSDCyZ4oenFjYSc6ZXODPY+k310oBkgyQqOTi/XOWGCfoT/HZ5q4OU72uXy0
K/c7IK6yYUpgfqLBjo6urr6c/IXqr0scklp6F+iRAWZVJCl7A2DNUz0Qj5AyB4Ir
T+irzOIKKrwuAdsncx1Gn2iwxQ==
-----END PRIVATE KEY-----
"""
pkey_password = b"123456789"


@pytest.fixture(scope="session")
def test_data_dir() -> Path:
    return (Path(__file__).parent.parent / "test_data").resolve()


@pytest.fixture(scope="session")
def unstream_cmd() -> Path:
    if sys.platform == "win32":
        unstream_path = which("unstream.exe")
        return (
            Path(unstream_path)
            if unstream_path
            else Path(__file__).parent.parent / "build" / "Release" / "unstream.exe"
        )
    else:
        unstream_path = which("unstream")
        return (
            Path(unstream_path)
            if unstream_path
            else Path(__file__).parent.parent / "build" / "unstream"
        )


@pytest.fixture(scope="session", params=archive_files)
def input_file(test_data_dir, request) -> Path:
    return test_data_dir / request.param


@pytest.fixture(scope="session", params=methods)
def method(request) -> str:
    return request.param


@pytest.fixture(scope="session")
def valid_archive(test_data_dir) -> Path:
    return test_data_dir / archive_files[0]


@pytest.fixture(scope="session")
def output_hash(archive: Path) -> str:
    if archive.name.startswith("archive_aes"):
        return "edcb3c7bf0901ba2d8581179bc8a69dc26bce571"
    elif archive.name.startswith("archive_des"):
        return "8ad404def35c4ed554e350cb36e331a779901052"
    else:
        return "deadbeef"


@pytest.fixture(scope="session")
def valid_recipient_keys(test_data_dir) -> List[Path]:
    return [test_data_dir / "recipient1-key.pem", test_data_dir / "recipient2-key.pem"]


@pytest.fixture(
    scope="session",
    params=[
        "recipient1-key.pem",
        "recipient2-key.pem",
        recipient1_key,
    ],
)
def valid_recipient_key(request, test_data_dir) -> Union[Path, bytes]:
    if isinstance(request.param, str):
        return test_data_dir / request.param
    else:
        return request.param


@pytest.fixture(
    scope="session",
    params=[
        "recipient1-key.enc.pem",
        recipient1_enc_key,
    ],
)
def valid_recipient_key_encrypted(request, test_data_dir) -> Union[Path, bytes]:
    if isinstance(request.param, str):
        return test_data_dir / request.param
    else:
        return request.param


@pytest.fixture(scope="session")
def key_password() -> bytes:
    return pkey_password


@pytest.fixture(scope="session")
def invalid_recipient_keys(test_data_dir) -> List[Path]:
    return [
        test_data_dir / "recipient3-key.pem",
    ]


@pytest.fixture(
    scope="session",
    params=[
        "recipient3-key.pem",
        recipient3_key,
    ],
)
def invalid_recipient_key(request, test_data_dir) -> Union[Path, bytes]:
    if isinstance(request.param, str):
        return test_data_dir / request.param
    else:
        return request.param
