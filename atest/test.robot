*** Settings ***
Library    CryptoLibrary
Library    Collections


*** Variables ***
${crypto}    crypt:t6dpLk9ed6DyzciMgZkoZ8H56UA97ZLxidSaHjXjGlACouzedTUIThCqFY69/DDGjmybcJGDo5eUsA26TqfxUHgXuA==
${long}
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    11223344556677889900998877665544332211
...    separator=
${long_crypt}
...    crypt:YM+bcv4WQ11jxmDGvH4ZA3jX6tg77SrN
...    LxxMth+Xj0kUF36Ryls1kYMP77QRNxzjpMCa5/
...    qbzTo/YeLfVpmcz8CgvjMZT/19zUOzXd+1nSmg
...    jE43DUJEtAJNWwvXjvqa/MNiqJpvmXQqVlBwku
...    wrStzO9iJVUh95oHbEIjRppfZNpBLEVrvhq7Xj
...    JR8uvFhrnamNwfttC3ib/gQlMsp/G1KS6LIkgI
...    APmZvTYqutWkShRJI3gZipKKgSHoMsUDTNO7bK
...    MRvji3u6SWEhvGPPfP4uuqbCE3W3on/EMKGXzk
...    vhYtUXPE+kYagewvIVmPXuJk8D7ImSST1aBOAo
...    p6Jw1TxqjMTa/xCVTb62Pu6Lx1XVB5QhEJ4UnV
...    L6S8d+Wae/6FWz9F29MYTvSSpKKkh40DzZcK8J
...    OfkVup9plz/ad8or8nEGLjwDNmY/B1oCfbRHSO
...    fQf8atAeBfM/q2kMmJd7nM6wPyrzhBY+eOIX9c
...    7m05bY+CkFZBF0KCfbeHlk9A9erdjo/AMQAdzS
...    /TtyQ0X+b65J9vfWXZz9DzoSjO+eByb/0y2Yqf
...    j6kyHfj6KBMvQ/8AyhnX08q5dZpyq65yZwvxV4
...    qnx+YS0LLy3CJ2/EKwbkFq5nfMwlVjh2E5m8cX
...    FYNoIscXRIik0TscIKt1yBftAKJ87amjnFPXKQ
...    AYLFvF97/oeBkXtoPOhWJ5UdlYa0OTYad4J3SB
...    MsJF26Aot/HXENbhRNwRyS7z1FJCFJIpybSUXB
...    z46HB7lNMdcZXoIXJVxIIX49mtK5zYhvFHwEVu
...    OJviVA5eelw6WvjH0TF66m4PDVbnYDku8XvB4x
...    DOjwYQNZGI0/icDrkCVS0NAXCm5JdcoBAGf6RG
...    2ME/Alw4KUXKK9BY0ftpnZD5E2sR67okj8NHgO
...    g2AyAtcmJRyUgRzEalJvVAI05mOvjueZgaZmP0
...    hVxCziROmqinhzTbxbMTCJ7vJ/6br6TIzUtNbp
...    qDBqV1TqBCUwoheOiB236OxrFAsLprV7dFC4/3
...    uhpRuiHdJdPJryXBDYNO1WXY2zUs1ObuE6D8zT
...    IlzYCdHfxTGgPNCjnLUg==
...    separator=



*** Test Cases ***
Test
    Log     ${crypto}
    @{list}    Set Variable    one    two    ${23}
    ${decrypted}    Get Decrypted Text    ${crypto}
    ${assigned}    Set Variable    ${decrypted}
    Log To Console    ${assigned}
    ${long_decrypted}    Get Decrypted Text    ${long_crypt}
    @{dec_list}    Set Variable    ${long_decrypted}    ${decrypted}
    Log    ${dec_list}
    &{dict}    Create Dictionary    value=${decrypted}
    FOR    ${a}    ${b}    IN ZIP    ${dec_list}    ${dec_list}
        Log To Console    ${a}
        Should Be Equal    ${a}    ${b}
    END
    WHILE    '${decrypted}' == '1234567890987654321'
        ${decrypted}    Set Variable    No
    END
    &{d}    Set Variable    ${dict}





