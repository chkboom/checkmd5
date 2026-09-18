-- mctypes.ads - Custom types used throughout the program.
-- This file is a part of the checkmd5 tool.
--
-- Copyright (C) 2026 by AK-47.
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
with Interfaces; use Interfaces;
package McTypes is

   subtype Large_Natural is Long_Long_Integer range 0 .. Long_Long_Integer'Last;

   type Array_U8 is array(Natural range<>) of Unsigned_8;
   type Array_U16 is array(Natural range<>) of Unsigned_16;
   type Array_U32 is array(Natural range<>) of Unsigned_32;
   type Array_U64 is array(Natural range<>) of Unsigned_64;

end McTypes;
