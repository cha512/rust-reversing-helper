# rust-reversing-helper

A ida script to help reversing rust binary

![](https://github.com/cha5126568/rust-reversing-helper/blob/master/pic/diff.png)

## 사용법

1. https://github.com/luser/rustfilt
이거 설치해서 스크립트에 있는 rustfilt 경로 바꿔주세요.
2. IDA 7.0 에서 스크립트 불러와주면 끝!

## 주의사항
1. 기본적 ELF x64만 지원합니다. 
DWARF 정보가 있으면 디맹글링 정도는 될지 모르겠지만, 테스트해보진 않았습니다.

## 기능
1. 함수이름을 전부 디맹글링 해줍니다. (function name demangle)
2. 사용되는 문자열을 잡아줍니다. (string recovery)

## TODO
- [ ] 다양한 바이너리로 테스트
- [ ] exe도 지원.
