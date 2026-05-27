import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { FileWarning } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  submitDmcaClaim,
  type DmcaClaimIn,
} from "@/api/endpoints/dmca";

interface FormValues {
  claimant_name: string;
  claimant_email: string;
  claimant_address: string;
  claimant_phone: string;
  content_url: string;
  content_type: DmcaClaimIn["content_type"];
  original_work_description: string;
  sworn_statement: boolean;
  good_faith_belief: boolean;
  signature: string;
}

export default function DmcaClaimForm() {
  const navigate = useNavigate();
  const [contentType, setContentType] = useState<DmcaClaimIn["content_type"]>("other");

  const {
    register,
    handleSubmit,
    setValue,
    watch,
    formState: { errors },
  } = useForm<FormValues>({
    defaultValues: {
      claimant_name: "",
      claimant_email: "",
      claimant_address: "",
      claimant_phone: "",
      content_url: "",
      content_type: "other",
      original_work_description: "",
      sworn_statement: false,
      good_faith_belief: false,
      signature: "",
    },
  });

  const swornStatement = watch("sworn_statement");
  const goodFaithBelief = watch("good_faith_belief");

  const mutation = useMutation({
    mutationFn: (data: DmcaClaimIn) => submitDmcaClaim(data),
    onSuccess: () => {
      toast.success("DMCA claim submitted successfully");
      navigate("/");
    },
    onError: (err: unknown) => {
      toast.error(
        err instanceof Error ? err.message : "Failed to submit DMCA claim",
      );
    },
  });

  const onSubmit = (values: FormValues) => {
    const payload: DmcaClaimIn = {
      claimant_name: values.claimant_name,
      claimant_email: values.claimant_email,
      claimant_address: values.claimant_address,
      claimant_phone: values.claimant_phone || undefined,
      content_url: values.content_url,
      content_type: contentType,
      original_work_description: values.original_work_description,
      sworn_statement: values.sworn_statement,
      good_faith_belief: values.good_faith_belief,
      signature: values.signature,
    };
    mutation.mutate(payload);
  };

  return (
    <div className="p-6 space-y-6 max-w-3xl mx-auto">
      <PageHeader
        title="Submit DMCA Takedown Request"
        description="Report content that infringes on your copyright"
      />

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Your Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileWarning className="h-5 w-5" />
              Your Information
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="claimant_name">Full Legal Name *</Label>
              <Input
                id="claimant_name"
                placeholder="Your full legal name"
                {...register("claimant_name", { required: "Name is required" })}
              />
              {errors.claimant_name && (
                <p className="text-sm text-destructive mt-1">{errors.claimant_name.message}</p>
              )}
            </div>
            <div>
              <Label htmlFor="claimant_email">Email Address *</Label>
              <Input
                id="claimant_email"
                type="email"
                placeholder="you@example.com"
                {...register("claimant_email", {
                  required: "Email is required",
                  pattern: {
                    value: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                    message: "Invalid email address",
                  },
                })}
              />
              {errors.claimant_email && (
                <p className="text-sm text-destructive mt-1">{errors.claimant_email.message}</p>
              )}
            </div>
            <div>
              <Label htmlFor="claimant_address">Mailing Address *</Label>
              <Textarea
                id="claimant_address"
                placeholder="Your full mailing address"
                rows={2}
                {...register("claimant_address", { required: "Address is required" })}
              />
              {errors.claimant_address && (
                <p className="text-sm text-destructive mt-1">{errors.claimant_address.message}</p>
              )}
            </div>
            <div>
              <Label htmlFor="claimant_phone">Phone Number (optional)</Label>
              <Input
                id="claimant_phone"
                type="tel"
                placeholder="+1 555-123-4567"
                {...register("claimant_phone")}
              />
            </div>
          </CardContent>
        </Card>

        {/* Infringing Content */}
        <Card>
          <CardHeader>
            <CardTitle>Infringing Content</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="content_url">Content URL *</Label>
              <Input
                id="content_url"
                type="url"
                placeholder="https://example.com/infringing-content"
                {...register("content_url", { required: "Content URL is required" })}
              />
              {errors.content_url && (
                <p className="text-sm text-destructive mt-1">{errors.content_url.message}</p>
              )}
            </div>
            <div>
              <Label htmlFor="content_type">Content Type *</Label>
              <Select
                value={contentType}
                onValueChange={(val) => setContentType(val as DmcaClaimIn["content_type"])}
              >
                <SelectTrigger id="content_type">
                  <SelectValue placeholder="Select content type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="feed_post">Feed Post</SelectItem>
                  <SelectItem value="feed_media">Feed Media</SelectItem>
                  <SelectItem value="message_media">Message Media</SelectItem>
                  <SelectItem value="video">Video</SelectItem>
                  <SelectItem value="other">Other</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </CardContent>
        </Card>

        {/* Original Work */}
        <Card>
          <CardHeader>
            <CardTitle>Original Work Description</CardTitle>
          </CardHeader>
          <CardContent>
            <div>
              <Label htmlFor="original_work_description">
                Describe the original copyrighted work *
              </Label>
              <Textarea
                id="original_work_description"
                placeholder="Describe the original work that you believe is being infringed (minimum 20 characters)"
                rows={4}
                {...register("original_work_description", {
                  required: "Description is required",
                  minLength: {
                    value: 20,
                    message: "Description must be at least 20 characters",
                  },
                })}
              />
              {errors.original_work_description && (
                <p className="text-sm text-destructive mt-1">
                  {errors.original_work_description.message}
                </p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Legal Statements */}
        <Card>
          <CardHeader>
            <CardTitle>Legal Statements</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-start gap-3">
              <Checkbox
                id="sworn_statement"
                checked={swornStatement}
                onCheckedChange={(checked) =>
                  setValue("sworn_statement", checked === true)
                }
              />
              <Label htmlFor="sworn_statement" className="text-sm leading-relaxed">
                I swear, under penalty of perjury, that I am the copyright owner
                or am authorized to act on behalf of the owner of an exclusive
                right that is allegedly infringed. *
              </Label>
            </div>
            <div className="flex items-start gap-3">
              <Checkbox
                id="good_faith_belief"
                checked={goodFaithBelief}
                onCheckedChange={(checked) =>
                  setValue("good_faith_belief", checked === true)
                }
              />
              <Label htmlFor="good_faith_belief" className="text-sm leading-relaxed">
                I have a good faith belief that the use of the material in the
                manner complained of is not authorized by the copyright owner, its
                agent, or the law. *
              </Label>
            </div>
          </CardContent>
        </Card>

        {/* Electronic Signature */}
        <Card>
          <CardHeader>
            <CardTitle>Electronic Signature</CardTitle>
          </CardHeader>
          <CardContent>
            <div>
              <Label htmlFor="signature">
                Type your full legal name as your electronic signature *
              </Label>
              <Input
                id="signature"
                placeholder="Your full legal name"
                {...register("signature", { required: "Signature is required" })}
              />
              {errors.signature && (
                <p className="text-sm text-destructive mt-1">{errors.signature.message}</p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Submit */}
        <div className="flex justify-end">
          <Button
            type="submit"
            disabled={
              mutation.isPending ||
              !swornStatement ||
              !goodFaithBelief
            }
            size="lg"
          >
            {mutation.isPending ? "Submitting..." : "Submit DMCA Claim"}
          </Button>
        </div>
      </form>
    </div>
  );
}
