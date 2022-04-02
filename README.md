# u2f

u2f dongle implementation for MIT's 6.858 - Spring 2022

## Project Structure

- `arduino/`: arduino code that is uploaded to the actual dongle
- `server/`: test server in python
- `chrome/`: js that established a connection between the dongle and chrome via usb protocol
- `google-u2f-ref-code`: git submodule of google's u2f reference code

## References

[1] J. Lang, A. Czeskis, D. Balfanz, M. Schilder, and S. Srinivas, “Security Keys: Practical Cryptographic Second Factors for the Modern Web,” in Financial Cryptography and Data Security, vol. 9603, J. Grossklags and B. Preneel, Eds. Berlin, Heidelberg: Springer Berlin Heidelberg, 2017, pp. 422–440. doi: 10.1007/978-3-662-54970-4_25. Available: https://css.csail.mit.edu/6.858/2022/readings/u2f-fc.pdf

[2] Reference code for U2F specifications. FIDO Alliance, 2021. Accessed: Apr. 02, 2022. [Online]. Available: https://github.com/fido-alliance/google-u2f-ref-code
