-- console.ads - Console user interface handling.
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
with McTypes; use McTypes;

package Console is
   Machine_Friendly : Boolean := False;
   type Exit_Status is (Exit_OK, Exit_BadCheck,
     Exit_Aborted, Exit_System, Exit_BadList, Exit_BadCommand);
   procedure Print(Message : in String; End_Line : in Boolean := True);
   procedure Finish(Status : in Exit_Status);
   function Running return Boolean;
   task Progress is
      entry Prepare(Total_Targets : in Natural; Total_Bytes : in Large_Natural);
      entry Display(Next : out Large_Natural; Processed : in Large_Natural);
      entry Print(Message : in String; End_Line : in Boolean);
      entry Finish(Status : in Exit_Status);
   end Progress;
end Console;
