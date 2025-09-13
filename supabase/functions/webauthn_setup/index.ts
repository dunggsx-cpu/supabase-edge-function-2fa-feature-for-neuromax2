// supabase/functions/webauthn_setup/index.ts
import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { generateRegistrationOptions } from "npm:@simplewebauthn/server";
import { isoUint8Array } from "npm:@simplewebauthn/server/helpers";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Credentials": "true",
};
const supabase = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "",
  {
    auth: {
      persistSession: false,
    },
  }
);
const RP_NAME = "Neuromax";
const logStep = (step, details) => {
  const detailsStr = details ? ` - ${JSON.stringify(details)}` : "";
  console.log(`[WEBAUTHN_SETUP] ${step}${detailsStr}`);
};
serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: corsHeaders,
    });
  }
  if (req.method !== "POST") {
    return new Response("Method not allowed", {
      status: 405,
      headers: corsHeaders,
    });
  }
  try {
    const { user_id } = await req.json();
    if (!user_id) {
      return new Response(
        JSON.stringify({
          error: "Missing user_id",
        }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
    const { data: userData, error } = await supabase.auth.admin.getUserById(
      user_id
    );
    if (error || !userData?.user) {
      logStep("User not found", {
        error: error?.message,
      });
      return new Response(
        JSON.stringify({
          error: "User not found",
        }),
        {
          status: 404,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json",
          },
        }
      );
    }
    const user = userData.user;
    const origin = req.headers.get("origin") ?? "";
    let rpID;
    try {
      const url = new URL(origin);
      rpID = url.hostname;
      if (
        rpID === "localhost" &&
        (url.port === "3000" || url.port === "8000")
      ) {
        rpID = "localhost";
      }
    } catch {
      rpID = "localhost";
    }
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: rpID,
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.email ?? user.id,
      userDisplayName: user.email ?? user.id,
      attestationType: "none",
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "preferred",
      },
    });
    await supabase.from("user_security").upsert({
      user_id: user.id,
      current_challenge: options["challenge"] || options.challenge,
    });
    return new Response(JSON.stringify(options), {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  } catch (err) {
    logStep("ERROR", {
      error: err.message ?? String(err),
    });
    return new Response(
      JSON.stringify({
        error: "Server error",
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json",
        },
      }
    );
  }
});
