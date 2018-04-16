from django.core.signing import Signer

from django.utils.encoding import force_bytes
signer = Signer(key='6bk^r*93y$^fg#lzq_87(_4ig^u*j0f%^-x_6j==wi9w8p$ru9')
print(signer.sign(1))