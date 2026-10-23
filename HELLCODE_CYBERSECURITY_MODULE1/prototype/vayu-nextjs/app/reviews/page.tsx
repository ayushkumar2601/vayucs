import { Metadata } from "next";
import ReviewsView from "./ReviewsView";

export const metadata: Metadata = {
  title: "VAYU CRS — Security Code Reviews & Automated Triage",
  description: "Autonomous Cyber Reasoning System code review and verified diff triage console.",
};

export default function ReviewsPage() {
  return <ReviewsView />;
}
