-- checkmd5 - Tool for checking the integrity of multiple files as one unit.
-- Unlike md5sum, the user can abort the check by pressing Escape.
-- This tool also indicates progress and supports verbose logging to a file.
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

with Ada.Command_Line;
with Ada.Text_IO;
with Ada.Strings.Fixed;
with Ada.Calendar;
with Ada.Calendar.Formatting;
with Ada.Exceptions; use Ada.Exceptions;
with Checkmd5_Config;
with Console;
with Log;
with McHash;

procedure CheckMD5 is
   use Ada;
   package CLI renames Ada.Command_Line;
   use Ada.Strings.Fixed;
   package Cal renames Ada.Calendar;
   package CalFmt renames Ada.Calendar.Formatting;
   verbose : Boolean := False;
   ixArgFiles : Natural := CLI.Argument_Count + 1;
   Handled_Exception : exception;
   Command_Line_Help : exception;

   procedure SetExit(Status : in Console.Exit_Status; Write_Log : in Boolean := True) is
   begin
      Console.Finish (Status => Status);
      CLI.Set_Exit_Status (Code => Status'Enum_Rep);
      if Write_Log then
         Log.Write(Text => "Exit:" & Status'Enum_Rep'Image);
      end if;
   end SetExit;
begin
   ArgSwitches: for ixArg in 1 .. CLI.Argument_Count loop
      declare
         curArg : constant String := CLI.Argument(ixArg);
      begin
         if curArg = "--help" then
            raise Command_Line_Help;
         elsif curArg = "--force" then
            McHash.Force := True;
         elsif curArg = "--verbose" then
            verbose := True;
         elsif curArg = "--machine" then
            Console.Machine_Friendly := True;
         elsif Index(Source => curArg, Pattern => "--log=") = 1 and then not Log.isFileSet then
            Log.SetupFile(Path => Tail(Source => curArg, Count => curArg'Length-6));
         elsif curArg = "--" then -- End of flag arguments. Files start after this.
            ixArgFiles := ixArg + 1;
            exit ArgSwitches;
         else -- Files start here.
            ixArgFiles := ixArg;
            exit ArgSwitches;
         end if;
      end;
   end loop ArgSwitches;
   Log.Verbose_Mode := verbose;

   -- Make sure there is at least one list file on the command line. --
   if ixArgFiles > CLI.Argument_Count then
      raise Command_Line_Help with "No list files specified";
   end if;

   -- Log the start time and all of the list file names on the command line. --
   Log.Write(Text => "Start: " & CalFmt.Local_Image(Date => Cal.Clock, Include_Time_Fraction => True));
   Log.Write(Text => "Lists:", End_Line => False);
   for ixArg in ixArgFiles..CLI.Argument_Count loop
      Log.Write(Text => " ", End_Line => False);
      Log.Write(Text => CLI.Argument(Number => ixArg), End_Line => False);
   end loop;
   Log.Write(Text => "", End_Line => True);

   -- Obtain targets. --
   begin
      for ixArg in ixArgFiles..CLI.Argument_Count loop
         McHash.Add_Targets(List_Path => CLI.Argument(Number => ixArg));
      end loop;
   exception
      when X : others =>
         Log.Write(Text => Exception_Message (X), Output => Log.Log_Console);
         SetExit(Status => Console.Exit_BadList);
         raise Handled_Exception;
   end;

   -- Check all targets and exit with the status of the check. --
   declare
      Status : constant Console.Exit_Status := McHash.Check_Targets;
   begin
      SetExit(Status => Status);
   end;

exception
   when Handled_Exception =>
      null; -- Exit status already set to appropriate value. Just exit the program at this point.
   when X: Command_Line_Help =>
      declare
         Message : constant String := Exception_Message (X => X);
         BadCommand : constant Boolean := (Message'Length > 0);
      begin
         if BadCommand then
            Log.Write(Text => "ERROR: " & Message, Output => Log.Log_Console);
         end if;
         Text_IO.Put_Line (File => Text_IO.Standard_Error,
           Item => "checkMD5 - Version " & Checkmd5_Config.Crate_Version);
         Text_IO.Put_Line (File => Text_IO.Standard_Error,
           Item => "Usage: checkmd5 [--force] [--verbose] [--machine] [--log=file] [--] file [...]");
         SetExit(Status => Console.Exit_BadCommand, Write_Log => BadCommand);
      end;
   when X : Text_IO.Name_Error | Text_IO.Device_Error | Text_IO.Data_Error | Text_IO.End_Error =>
      Log.Write(Text => "ERROR: " & Exception_Message (X), Output => Log.Log_Console);
      SetExit(Status => Console.Exit_System);
end CheckMD5;
