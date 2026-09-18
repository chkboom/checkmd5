-- mchash.adb - Hash collection and checking.
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

with Ada.Characters; use Ada.Characters;
with Ada.Characters.Handling; use Ada.Characters.Handling;
with Ada.Characters.Latin_1;
with Ada.Containers.Vectors;
with Ada.Strings; use Ada.Strings;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Strings.Fixed; use Ada.Strings.Fixed;
with Ada.Text_IO;
with Ada.Exceptions;
with Ada.Streams;
with GNAT.MD5;
with Interfaces.C;

with Platform;
with Console; use Console;
with Log;

package body McHash is

   package Target_Vectors is new
     Ada.Containers.Vectors(Index_Type => Natural, Element_Type => Target);
   Targets : Target_Vectors.Vector;
   Total_Bytes : Large_Natural := 0;

   procedure Add_Targets(List_Path : in String) is
      use Ada;
      List_File : Text_IO.File_Type;
      Line_No : Natural := 0;
      Col_No : Natural := 0;
      function Is_Whitespace(Item : in Character) return Boolean is
      begin
         if Item = ' ' or else Item = Latin_1.HT then
            return True;
         end if;
         return False;
      end Is_Whitespace;
      function Error(Message : in String) return String is
      begin
         return "ERROR (" & List_Path & ": "
           & Line_No'Image & "," & Col_No'Image & "): " & Message;
      end Error;
   begin
      Text_IO.Open(File => List_File, Name => List_Path, Mode => Text_IO.In_File);
      while not Text_IO.End_Of_File(List_File) loop
         Col_No := 1;
         Line_No := Line_No + 1;
         declare
            Line : constant String := Text_IO.Get_Line(File => List_File);
            New_Target : Target;
         begin
            -- Skip whitespace at the start --
            while Is_Whitespace(Item => Line(Col_No)) loop
               Col_No := Col_No + 1;
            end loop;

            -- Ensure the line is long enough to have a hash and a file name. --
            if (Line'Length - Col_No) < (Hash_Hex_Size + 1 + 1) then
               raise Error_Line_Too_Short with "Line too short for processing";
            end if;

            -- Validate and collect hex digits. --
            for I in 1..Hash_Hex_Size loop
               if not Is_Hexadecimal_Digit(Item => Line(Col_No)) then
                  raise Error_Invalid_Hex with "Invalid hexadecimal hash string";
               end if;
               New_Target.Hash(I) := To_Upper(Item => Line(Col_No));
               Col_No := Col_No + 1;
            end loop;

            -- Ensure there is at least a single white space. Skip whitespace. --
            if not Is_Whitespace(Item => Line(Col_No)) then
               raise Error_No_Space with "Missing space";
            end if;
            while Is_Whitespace(Item => Line(Col_No)) loop
               Col_No := Col_No + 1;
            end loop;

            -- Asterisk (ignored here, used to denote binary file) --
            if Line(Col_No) = '*' then
               Col_No := Col_No + 1;
            end if;
            -- Stat and path copy --
            if Col_No > Line'Length then
               raise Error_No_Path with "Missing path or file name";
            end if;
            declare
               Path_String : constant String := Line(Col_No..Line'Length);
               FI : constant Platform.File_Info := Platform.Get_File_Info(Path => Path_String);
            begin
               New_Target.Size := FI.Size;
               New_Target.Block_Size := FI.Block_Size;
               New_Target.Path := To_Unbounded_String(Path_String);
               Trim(Source => New_Target.Path, Side => Both);
               Total_Bytes := Total_Bytes + New_Target.Size;
            end;

            Targets.Append(New_Item => New_Target);
         end;
      end loop;
   exception
      when others => raise;
   end Add_Targets;

   function Check_Targets return Console.Exit_Status is
      use Interfaces.C;
      use Ada.Exceptions;
      Prog_Next : Large_Natural := 0;
      Checked_Bytes : Large_Natural := 0;
      Passed_Targets : Natural := 0;
      Passed_Bytes : Large_Natural := 0;
      Status : Console.Exit_Status := Console.Exit_OK;
      FD : int := 0;
   begin
      Console.Progress.Prepare(Total_Targets => Natural(Targets.Length), Total_Bytes => Total_Bytes);
      Target_Loop: for T of Targets loop
         Log.Write(Output => Log.Verbose_Console, Text => "Target: " & T.Hash & " " & To_String(T.Path));

         declare
            use Ada.Streams;
            Buffer : Stream_Element_Array(1 .. T.Block_Size);
            ReadSize : Stream_Element_Count := T.Block_Size;
            Remaining : Large_Natural := T.Size;
            MD5_Context : GNAT.MD5.Context := GNAT.MD5.Initial_Context;
            T_Path : constant String := To_String(T.Path);
         begin
            FD := Platform.File_Open_Sequential_ReadOnly(Path => To_String(T.Path));
            Hash_Loop: while Remaining > 0 loop
               if Remaining < Large_Natural(ReadSize) then
                  ReadSize := Stream_Element_Count(Remaining);
               end if;
               ReadSize := Platform.File_Read(fd => FD, Buffer => Buffer(1..ReadSize));

               GNAT.MD5.Update(C => MD5_Context, Input => Buffer(1..ReadSize));

               Checked_Bytes := Checked_Bytes + Large_Natural(ReadSize);
               Remaining := Remaining - Large_Natural(ReadSize);
               if Checked_Bytes >= Prog_Next then
                  Console.Progress.Display(Next => Prog_Next, Processed => Checked_Bytes);
                  if not Console.Running then
                     Status := Console.Exit_Aborted;
                     exit Target_Loop;
                  end if;
               end if;
            end loop Hash_Loop;

            declare
               Calc_Hash : constant String := To_Upper(GNAT.MD5.Digest(C => MD5_Context));
            begin
               if Calc_Hash = T.Hash then
                  Passed_Targets := Passed_Targets + 1;
                  Passed_Bytes := Passed_Bytes + T.Size;
                  Log.Write(Text => "Passed: " & Calc_Hash & " " & T_Path, Output => Log.Verbose_Console);
               else
                  Log.Write(Text => "Failed: " & Calc_Hash & " " & T_Path, Output => Log.Verbose_Console);
                  Ada.Text_IO.Put_Line(T_Path & ": Checksum mismatch");
                  Status := Console.Exit_BadCheck;
               end if;
            end;
         exception
            when E: others =>
               Log.Write(Output => Log.Log_Console, Text => "Exception:" & Exception_Message(E) & ":" & T_Path);
               Status := Console.Exit_System;
         end;
         Platform.File_Close(fd => FD);

         exit Target_Loop when Status /= Console.Exit_OK and then not Force;
         exit Target_Loop when not Console.Running;
      end loop Target_Loop;

      Console.Progress.Finish(Status => Status);
      declare
         use Ada.Strings.Fixed;
         function NumStr(I : in Large_Natural) return String is ( Trim(Source => I'Image, Side => Left) );
         function NumStr(I : in Natural) return String is ( Trim(Source => I'Image, Side => Left) );
      begin
         Log.Write(Text => "Result: " & NumStr(Passed_Targets) & "/" & NumStr(Natural(Targets.Length))
           & " targets (" & NumStr(Passed_Bytes) & "/" & NumStr(Total_Bytes) & " bytes) passed",
           Output => Log.Verbose_Console);
      end;
      return Status;
   end Check_Targets;

end McHash;
