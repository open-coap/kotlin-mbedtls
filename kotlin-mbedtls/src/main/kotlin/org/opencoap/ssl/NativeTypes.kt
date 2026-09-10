/*
 * Copyright (c) 2022-2026 kotlin-mbedtls contributors (https://github.com/open-coap/kotlin-mbedtls)
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opencoap.ssl

import com.sun.jna.Pointer

/*
Mapping for C types that jna has no direct equivalent for.
 */

// size_t is 8 bytes on every platform this library ships native libraries for: linux-x86-64,
// linux-aarch64, darwin and win32-x86-64. Windows is LLP64, so its long is 4 bytes while size_t
// is still 8. NativeTypesTest guards this against a future 32-bit target.
internal const val SIZE_T_LEN = 8L

// Reads a size_t that mbedtls wrote through a length out-parameter. Pointer.getLong reads native
// memory in native byte order, so there is no endianness to handle here. Narrowed to Int like
// every other length in this binding: mbedtls only writes buffer sizes through these.
internal fun Pointer.getSizeT(offset: Long = 0): Int = getLong(offset).toInt()
