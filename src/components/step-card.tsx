import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { ReactNode } from "react";

interface StepCardProps {
  stepNumber: number;
  title: string;
  children: ReactNode;
  stepColor: string;
  onAction?: () => void;
  actionLabel?: string;
  actionIcon?: ReactNode;
  explanation?: ReactNode;
}

export function StepCard({
  stepNumber,
  title,
  children,
  stepColor,
  onAction,
  actionLabel,
  actionIcon,
  explanation
}: StepCardProps) {
  // Map step numbers to actual Tailwind color classes
  const getStepColors = (step: number) => {
    switch (step) {
      case 1: return {
        bg: 'bg-green-50',
        border: 'border-green-500',
        headerBg: 'bg-green-500',
        buttonBg: 'bg-green-500 hover:bg-green-600',
        explanationBg: 'bg-green-100 border-green-300',
        explanationText: 'text-green-800',
        stepNumberText: 'text-green-500'
      };
      case 2: return {
        bg: 'bg-blue-50',
        border: 'border-blue-500',
        headerBg: 'bg-blue-500',
        buttonBg: 'bg-blue-500 hover:bg-blue-600',
        explanationBg: 'bg-blue-100 border-blue-300',
        explanationText: 'text-blue-800',
        stepNumberText: 'text-blue-500'
      };
      case 3: return {
        bg: 'bg-red-50',
        border: 'border-red-500',
        headerBg: 'bg-red-500',
        buttonBg: 'bg-red-500 hover:bg-red-600',
        explanationBg: 'bg-red-100 border-red-300',
        explanationText: 'text-red-800',
        stepNumberText: 'text-red-500'
      };
      case 4: return {
        bg: 'bg-purple-50',
        border: 'border-purple-500',
        headerBg: 'bg-purple-500',
        buttonBg: 'bg-purple-500 hover:bg-purple-600',
        explanationBg: 'bg-purple-100 border-purple-300',
        explanationText: 'text-purple-800',
        stepNumberText: 'text-purple-500'
      };
      case 5: return {
        bg: 'bg-orange-50',
        border: 'border-orange-500',
        headerBg: 'bg-orange-500',
        buttonBg: 'bg-orange-500 hover:bg-orange-600',
        explanationBg: 'bg-orange-100 border-orange-300',
        explanationText: 'text-orange-800',
        stepNumberText: 'text-orange-500'
      };
      case 6: return {
        bg: 'bg-teal-50',
        border: 'border-teal-500',
        headerBg: 'bg-teal-500',
        buttonBg: 'bg-teal-500 hover:bg-teal-600',
        explanationBg: 'bg-teal-100 border-teal-300',
        explanationText: 'text-teal-800',
        stepNumberText: 'text-teal-500'
      };
      default: return {
        bg: 'bg-gray-50',
        border: 'border-gray-500',
        headerBg: 'bg-gray-500',
        buttonBg: 'bg-gray-500 hover:bg-gray-600',
        explanationBg: 'bg-gray-100 border-gray-300',
        explanationText: 'text-gray-800',
        stepNumberText: 'text-gray-500'
      };
    }
  };

  const colors = getStepColors(stepNumber);

  return (
    <Card className={cn("overflow-hidden border-2", colors.border)}>
      <CardHeader className={cn("text-white px-6 py-4", colors.headerBg)}>
        <h3 className="text-xl font-semibold flex items-center text-white">
          <span className={cn("bg-white rounded-full w-8 h-8 flex items-center justify-center text-sm font-bold mr-3", colors.stepNumberText)}>
            {stepNumber}
          </span>
          {title}
        </h3>
      </CardHeader>
      <CardContent className={cn("p-6", colors.bg)}>
        {explanation && (
          <div className={cn("border rounded-lg p-4 mb-6", colors.explanationBg)}>
            <div className={colors.explanationText}>
              {explanation}
            </div>
          </div>
        )}
        
        {children}
        
        {onAction && actionLabel && (
          <div className="mt-6">
            <Button
              onClick={onAction}
              className={cn("text-white transition-colors", colors.buttonBg)}
              data-testid={`step-${stepNumber}-action`}
            >
              {actionIcon}
              {actionLabel}
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
