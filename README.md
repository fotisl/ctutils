# Javascript CT implementation

CTUtils is a CT implementation for Javascript. It currently supports the protocol as defined in RFC6962.

There are classes for all structures defined in the specification with methods for verification, binary parsing and dumping where appropriate.

There are also two different helper classes that perform common operations on CT log lists and certificates.

# Installation

Use:

    npm run build

to build the module.

Use:

    npm run generate-docs

to generate the documentation

# Requirements

If running under node, you will need a fetch and a webcrypto polyfill, such as node-fetch and node-webcrypto-ossl. After importing them, you need to set both engines using setFetch and setWebCrypto. As an example, you can use the following:

    const fetch = require('node-fetch');
    const WebCrypto = require('node-webcrypto-ossl');
    const CTUtils = require('ctutils');

    const webcrypto = new WebCrypto();

    CTUtils.setFetch(fetch);
    CTUtils.setWebCrypto(webcrypto);

# Usage

Please see the generated documentation for sample usage.

You can also check the examples in the examples/ folder.

For HTML examples please check:

* [Get CT log accepted roots](examples/html/GetRoots/index.html)
* [Real-time fetching of logged certificates](examples/html/FetchNewCerts/index.html)

# License

Copyright (c) 2018, Fotis Loukos <me@fotisl.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

