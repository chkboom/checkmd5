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

with Ada.Text_IO;
with Console;

package body Log is
   use Ada;
   logFile : Text_IO.File_Type;

   procedure SetupFile(Path : in String) is
   begin
      Text_IO.Create(File => logFile, Mode => Text_IO.Out_File, Name => Path);
   end SetupFile;

   function isFileSet return Boolean is
   begin
      return Text_IO.Is_Open(logFile);
   end isFileSet;

   procedure Write(Text: in String; End_Line : in Boolean := True; Output : in Output_Mode := Log_Only) is
   begin
      if Text_IO.Is_Open(logFile) then
         Text_IO.Put(File => logFile, Item => Text);
         if End_Line then
            Text_IO.New_Line(File => logFile);
         end if;
      end if;
      if Output = Log_Console or else (Output = Verbose_Console and then Verbose_Mode) then
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
