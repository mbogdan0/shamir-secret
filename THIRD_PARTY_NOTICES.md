# Third Party Notices

This project implements SLIP-0039 using the public SatoshiLabs specification, wordlist, and Trezor reference vectors. The vendored test vectors in `test/fixtures/slip39-vectors.json` and portions of the algorithm structure and constants are adapted from `trezor/python-shamir-mnemonic`, which is distributed under the MIT License.

The build and development toolchain uses `vite`, which is distributed under the MIT License. It is a development dependency and is not bundled into the generated offline HTML runtime.
The runtime hex encoder and decoder use `@scure/base`, which is distributed under the MIT License and bundled into the generated offline HTML runtime.

`@scure/base` copyright:

```text
Copyright (c) 2022 Paul Miller (https://paulmillr.com)
```

```text
Copyright (c) 2018 Andrew R. Kozlik

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
