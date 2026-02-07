# TODO
First we need to create a C++ application which allows including command line arguments to generate a OTP code and output a QR image of the otp code along with the manual entry codes for Google authenticator and Microsoft Authenticator support

We also need to include a command line argument for testing this OTP code and verify that the code on the Authenticator end is usable and functioning properly and synchronized properly as well

along with a secure way for to be encrypted and decrypted in runtime along with holding it memory in a private field

Should use a Multi encryption bundling process with a encryption inside a encryption about 3 layers

Should be relatively secured to ensure no potential memory leaks or sensitive access to the OTP code should have a secure way of saving it and storing and opening it without allowing one to reverse engineer access to it.   