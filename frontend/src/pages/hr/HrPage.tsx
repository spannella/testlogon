import { useState } from "react";
import { Briefcase } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PositionsPanel } from "./PositionsPanel";
import { EmploymentsPanel } from "./EmploymentsPanel";
import { PayrollPanel } from "./PayrollPanel";

/**
 * OFBiz HR / Payroll (HRM) admin console.
 *
 * Three tabs over the LIVE /ui/hr backend:
 *   - Positions  (CRUD + status transitions)
 *   - Employments (create / terminate, party-linked)
 *   - Payroll    (create → approve → post lifecycle + line drill-down)
 *
 * Feature flags default OFF; when a panel's first query 404/503s we surface a
 * clear "module not enabled" state instead of leaving the user with an error.
 */
export default function HrPage() {
  const [hrDisabled, setHrDisabled] = useState(false);
  const [payrollDisabled, setPayrollDisabled] = useState(false);

  if (hrDisabled) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="HR & Payroll"
          description="Positions, employments, and payroll administration."
        />
        <EmptyState
          icon={<Briefcase className="h-10 w-10" />}
          title="HR module is not enabled"
          description="The HR/Payroll module is turned off for this environment. Ask a root operator to enable HR_ENABLED to use positions, employments, and payroll."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="HR & Payroll"
        description="Positions, employments, and payroll administration."
      />
      <Tabs defaultValue="positions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="positions">Positions</TabsTrigger>
          <TabsTrigger value="employments">Employments</TabsTrigger>
          <TabsTrigger value="payroll">Payroll</TabsTrigger>
        </TabsList>

        <TabsContent value="positions">
          <PositionsPanel onDisabled={() => setHrDisabled(true)} />
        </TabsContent>

        <TabsContent value="employments">
          <EmploymentsPanel onDisabled={() => setHrDisabled(true)} />
        </TabsContent>

        <TabsContent value="payroll">
          {payrollDisabled ? (
            <EmptyState
              icon={<Briefcase className="h-10 w-10" />}
              title="Payroll is not enabled"
              description="The payroll sub-module is turned off. Ask a root operator to enable HR_PAYROLL_ENABLED to create and post payroll runs."
            />
          ) : (
            <PayrollPanel
              onDisabled={() => setPayrollDisabled(true)}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
