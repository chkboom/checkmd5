-- platform.adb - Platform interface support scaffold.
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

with Interfaces.C; use Interfaces.C;
with Interfaces.C.Strings; use Interfaces.C.Strings;

package body Platform is

   function Page_Size return Natural is
      function platformPageSize return long
        with Import => True, Convention => C, External_Name => "platformPageSize";
      CR : constant long := platformPageSize;
   begin
      if CR < 0 then
         raise Page_Size_Error;
      end if;
      return Natural(platformPageSize);
   end Page_Size;

   function Get_File_Info(Path : String) return File_Info is
      FI : File_Info;

      type platform_stat is record
         size : long_long;
         blksize : size_t;
      end record
        with Convention => C_Pass_By_Copy;
      function platformStat (path : chars_ptr; pstat : access platform_stat) return int
        with Import => True,  Convention => C, External_Name => "platformStat";
      statrec : aliased platform_stat;
      C_Path : chars_ptr;
      CR : int := -1;
   begin
      C_Path := New_String(Path);
      CR := platformStat(path => C_Path, pstat => statrec'Access);
      Free(Item => C_Path);
      if CR /= 0 then
         raise Stat_Error;
      end if;
      FI.Size := Large_Natural(statrec.size);
      FI.Block_Size := Stream_Element_Count(statrec.blksize);
      return FI;
   end Get_File_Info;

   function File_Open_Sequential_ReadOnly(Path : in String) return int is
      function platformFileOpenSequentialRO(path : chars_ptr) return int
        with Import => True, Convention => C, External_Name => "platformFileOpenSequentialRO";
      C_Path : chars_ptr;
      CR : int := -1;
   begin
      C_Path := New_String(Path);
      CR := platformFileOpenSequentialRO(path => C_Path);
      if CR < 0 then
         raise File_Open_Error;
      end if;
      return CR;
   end File_Open_Sequential_ReadOnly;

   function File_Read(fd : in int; Buffer : in out Stream_Element_Array) return Stream_Element_Count is
      function platformFileRead(fd : int; buffer : in out Stream_Element_Array; size : size_t) return long_long
        with Import => True, Convention => C, External_Name => "platformFileRead";
      CR : long_long := -1;
   begin
      CR := platformFileRead(fd => fd, buffer => Buffer, size => Buffer'Length);
      if CR < 0 then
         raise File_IO_Error;
      end if;
      return Stream_Element_Count(CR);
   end File_Read;
end Platform;
