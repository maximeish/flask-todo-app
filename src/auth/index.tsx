import { Button } from "@chakra-ui/button";
import { Text } from "@chakra-ui/layout";
import React, { useState } from "react";
import Login from "./Login";
import Signup from "./Signup";

function Authentication() {
  const [page, setPage] = useState("");
  return (
    <>
      <Button onClick={() => setPage("login")}>Login</Button>
      <Button onClick={() => setPage("signup")}>Signup</Button>
      <div>
        {page === "login" ? (
          <Login />
        ) : page === "signup" ? (
          <Signup />
        ) : (
          <Text>Select action</Text>
        )}
      </div>
    </>
  );
}

export default Authentication;
