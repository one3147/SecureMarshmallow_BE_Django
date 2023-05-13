from django.test import TestCase
import jwt
decoded_token = jwt.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIsImV4cCI6MTY4Mzk4NDIwMywiaWF0IjoxNjgzOTgwNjAzLCJqdGkiOiJhZmUxNDU1M2JiNWE0ZjQyOGFhMDU3NzMyODk4ZGNiMiIsInVzZXJfaWQiOiJhZG1pbiJ9.zIdQBA_7x8GfJnWOAWWRsHh_EC1bFqKWt-uQv0tKfmA", algorithms=['HS256'], verify=True)
id = decoded_token.get('user_id')
print(id)