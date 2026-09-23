-- log.adb - Log file and logging managemenet.
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

with Ada.Text_IO.Editing;
with Ada.Real_Time;
with Ada.Strings.Fixed;
with Console;

package body Log is
   use Ada;
   use Ada.Real_Time;
   logFile : Text_IO.File_Type;
   Start_Time : constant Time := Clock;

   procedure SetupFile(Path : in String) is
   begin
      Text_IO.Create(File => logFile, Mode => Text_IO.Out_File, Name => Path);
   end SetupFile;

   function isFileSet return Boolean is
   begin
      return Text_IO.Is_Open(logFile);
   end isFileSet;

   procedure Write(Text: in String; Part : in Line_Part := Line_Whole; Mode : in Output_Mode := Log_Only) is
      Start_Line : constant Boolean := (Part = Line_Whole or else Part = Line_Start);
      End_Line : constant Boolean := (Part = Line_Whole or else Part = Line_End);
   begin
      if Text_IO.Is_Open(logFile) then
         if Start_Line then
            declare
               use Ada.Strings, Ada.Strings.Fixed;
               type Seconds is delta 0.001 digits 15;
               package Edit_IO is new Text_IO.Editing.Decimal_Output(Num => Seconds);
               Time_String : String := "ZZZZZZZZZ999.999";
               Picture : constant Text_IO.Editing.Picture
                  := Text_IO.Editing.To_Picture (Time_String);
            begin
               Edit_IO.Put(To => Time_String, Pic => Picture,
                 Item => Seconds(To_Duration(Clock - Start_Time)));
               Text_IO.Put (File => logFile,
                  Item => '[' & Trim(Source => Time_String, Side => Left) & "] ");
            end;
         end if;
         Text_IO.Put(File => logFile, Item => Text);
         if End_Line then
            Text_IO.New_Line(File => logFile);
            Text_IO.Flush(File => logFile);
         end if;
      end if;
      if Mode = Log_Console or else (Mode = Verbose_Console and then Verbose_Mode) then
         begin
            Console.Print(Message => Text, End_Line => End_Line);
         exception
            -- This procedure is used by exception handlers, so extinguish new exceptions.
            -- A broken pipe here can mean an unhandled exception if allowed to bubble up.
            when others => null;
         end;
      end if;
   end Write;
end Log;
