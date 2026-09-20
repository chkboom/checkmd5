-- platform.ads - Platform interface support scaffold.
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
pragma Ada_2022;
with Ada.Streams;
with Interfaces.C;
with McTypes; use McTypes;

package Platform is
   use Ada.Streams;
   use Interfaces.C;
   function Page_Size return Natural;

   type File_Info is record
      Size : Large_Natural;
      Block_Size : Stream_Element_Count;
   end record;
   function Get_File_Info(Path : String) return File_Info;

   function File_Open_Sequential_ReadOnly(Path : in String) return int;
   procedure File_Close(fd : in int)
     with Import => True, Convention => C, External_Name => "platformFileClose";
   function File_Read(fd : in int; Buffer : in out Stream_Element_Array) return Stream_Element_Count;

   Error_Page_Size, Error_Stat, Error_Open, Error_IO : exception;
end Platform;
