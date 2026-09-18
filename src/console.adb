-- console.adb - Console user interface handling.
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
with Ada.Characters; use Ada.Characters;
with Ada.Characters.Latin_1;
with Ada.Interrupts.Names;
with Ada.Strings; use Ada.Strings;
with Ada.Strings.Fixed; use Ada.Strings.Fixed;
with Ada.Text_IO;
with Log;

package body Console is

   use Ada.Interrupts.Names;
   pragma Unreserve_All_Interrupts; -- Ensure GNAT does not reserve SIGINT interrupt.
   protected Signals is
      function KeepGoing return Boolean;
      procedure Finish;
   private
      procedure Signal_Handler;
      pragma Attach_Handler(Signal_Handler, SIGHUP);
      pragma Attach_Handler(Signal_Handler, SIGINT); -- #2 reserved
      pragma Attach_Handler(Signal_Handler, SIGPIPE);
      pragma Attach_Handler(Signal_Handler, SIGALRM);
      pragma Attach_Handler(Signal_Handler, SIGTERM);
      -- pragma Attach_Handler(Signal_Handler, SIGTSTP); -- #20 reserved
      -- pragma Attach_Handler(Signal_Handler, SIGTTIN); -- #21 reserved
      -- pragma Attach_Handler(Signal_Handler, SIGTTOU); -- #22 reserved
      pragma Attach_Handler(Signal_Handler, SIGXCPU);
      pragma Attach_Handler(Signal_Handler, SIGXFSZ);
      pragma Attach_Handler(Signal_Handler, SIGVTALRM);
      -- pragma Attach_Handler(Signal_Handler, SIGPROF); -- #27 reserved
      pragma Attach_Handler(Signal_Handler, SIGUSR1);
      pragma Attach_Handler(Signal_Handler, SIGUSR2);
      KeepRunning : Boolean := True;
   end Signals;
   protected body Signals is
      function KeepGoing return Boolean is
      begin
         return KeepRunning;
      end KeepGoing;
      procedure Finish is
      begin
         KeepRunning := False;
      end Finish;

      procedure Signal_Handler is
      begin
         KeepRunning := False;
      end Signal_Handler;
   end Signals;

   function Running return Boolean is
   begin
      return Signals.KeepGoing and then not Progress'Terminated;
   end Running;

   procedure Finish(Status : in Exit_Status) is
   begin
      if not Progress'Terminated then
         Progress.Finish(Status => Status);
      end if;
   exception
      when others => null;
   end Finish;

   task body Progress is
      use Ada.Text_IO;
      Targets_Total : Natural := 0;
      Targets_Passed : Natural := 0;
      Bytes_Total : Large_Natural := 0;
      Bytes_Passed : Large_Natural := 0;
      Bytes_Processed : Large_Natural := 0;
      Byte_Gap : Large_Natural := 0;
      Need_NewLine : Boolean := False;
      function Current_Percentage return String is
         type Percentage is  delta 10.0 ** (-1) range 0.0 .. 100.0;
         Percent : constant Percentage := Percentage(100.0 * Float(Bytes_Processed) / Float(Bytes_Total));
      begin
         return Trim(Source => Percent'Image, Side => Left) & "%";
      end Current_Percentage;
   begin
      ProgressLoop: loop
         select
            accept Prepare(Total_Targets : in Natural; Total_Bytes : in Large_Natural) do
               Targets_Total := Total_Targets;
               Bytes_Total := Total_Bytes;
               Byte_Gap := Total_Bytes / 1000;
               if Byte_Gap = 0 then
                  Byte_Gap := 1; -- Prevent division by zero
               end if;
            end Prepare;
            if not Console.Machine_Friendly then
               Put_Line(File => Standard_Error, Item => "Press [Esc] to abort the integrity check.");
            end if;
         or
            accept Display(Next : out Large_Natural; Processed : in Large_Natural) do
               Bytes_Processed := Processed;
               Next := ((Processed / Byte_Gap) + 1) * Byte_Gap;
               if Next > Bytes_Total then
                  Next := Bytes_Total;
               end if;
            end Display;
            -- The display of the progress indicator.
            if Console.Machine_Friendly then
               Put_Line(File => Standard_Error, Item => Current_Percentage);
            else
               Put(File => Standard_Error,
                   Item => Latin_1.CR & "Checking: " & Current_Percentage);
               Need_NewLine := True;
            end if;
         or
            accept Finish(Status : in Exit_Status) do
               if not Progress'Terminated then
                  if Need_NewLine then
                     New_Line(File => Standard_Error);
                  end if;
                  case Status is
                     when Exit_OK =>
                        Put_Line(File => Standard_Error, Item => "The integrity check has passed.");
                     when Exit_BadCheck =>
                        Put_Line(File => Standard_Error, Item => "The integrity check has failed.");
                     when Exit_Aborted =>
                        Put_Line(File => Standard_Error, Item => "The integrity check was aborted.");
                        Log.Write(Text => "Aborted: " & Current_Percentage);
                     when others =>
                        Put_Line(File => Standard_Error, Item => "The integrity check could not be completed.");
                  end case;
               end if;
            end Finish;
            exit ProgressLoop;
         or
            delay 0.5; -- Timeout before polling for an <Esc> key press.
         end select;
         -- Every iteration, poll for and process an <Esc> for early exit.
         declare
            Answer : Character;
            Available : Boolean := False;
         begin
            Get_Immediate(Item => Answer, Available => Available);
            if Available and then Answer = Latin_1.ESC then
               Signals.Finish; -- Inform the master of the early exit via the protected object.
            end if;
         end;
      end loop ProgressLoop;
      Signals.Finish;
   end Progress;

end Console;
