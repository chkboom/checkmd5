-- log.ads - Log file and logging management.
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

package Log is
   Verbose_Mode : Boolean := False;
   type Output_Mode is (Log_Only, Log_Console, Verbose_Console);
   type Line_Part is (Line_Whole, Line_Start, Line_Text, Line_End);
   procedure SetupFile(Path : in String);
   function isFileSet return Boolean;
   procedure Write(Text: in String; Part : in Line_Part := Line_Whole; Mode : in Output_Mode := Log_Only);
end Log;
