-- mchash.ads - Hash collection and checking.
-- This file is a part of the checkmd5 tool.
--
-- Copyright (C) 2023-2024, 2026 by AK-47.
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
pragma Ada_2022;

with Ada.Strings.Unbounded;
with Ada.Streams;
with Console;
with McTypes; use McTypes;

package McHash is
   Force : Boolean := False;

   Hash_Size : constant := 16;
   Hash_Hex_Size : constant := Hash_Size * 2;
   type Target is record
      Size : Large_Natural;
      Block_Size : Ada.Streams.Stream_Element_Count;
      Hash : String(1..Hash_Hex_Size);
      Path : Ada.Strings.Unbounded.Unbounded_String;
   end record;

   procedure Add_Targets(List_Path : in String);
   function Check_Targets return Console.Exit_Status;
   Error_Line_Too_Short, Error_Invalid_Hex, Error_No_Space, Error_No_Path : exception;
end McHash;
