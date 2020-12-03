# IDASDK4D
Delphi source code for IDASDK và các plugin sẽ viết bằng Delphi cho IDA

Tạm thời repo chỉ chứa dbfix là plugin củ tôi viết cho IDA 6.x

Sẽ bổ sung các file cần thiết port từ IDA SDK C++ qua Delphi và 2 plugin dự tính: 

1. IDAPatch: patch ShowHelp action handler của IDA 7.x hiện tại, do Win10 không còn support WinHlp help file .hlp

Hook demangle_xxx function như plugin ReTypeDef hồi xưa của zyantific cho IDA 6.x

2. IDAHelp: support open CHM help file, Help2/3 file của Visual Studio và search Google, MSDN.

Cho phép thêm bớt, sửa list các CHM file, các link
 
