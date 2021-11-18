import React, { useState } from "react";
import {
  Flex,
  Heading,
  FormControl,
  FormLabel,
  Input,
  Button,
  CircularProgress,
  Box,
  Alert,
  AlertIcon,
  AlertDescription,
} from "@chakra-ui/react";

interface EMessageProps {
  message: any;
}

const ErrorMessage: React.FC<EMessageProps> = ({ message }) => (
  <Box my={4}>
    <Alert status="error" borderRadius={4}>
      <AlertIcon />
      <AlertDescription> {message}</AlertDescription>
    </Alert>
  </Box>
);

const Signup = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async () => {
    setIsLoading(true);
    try {
      await fetch("/login", {
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        method: "POST",
        body: JSON.stringify({ username: email, password }),
      })
        .then((res) => res.json())
        .then((data) => console.log(data))
        .catch((e) => console.log(e));
      setIsLoading(false);
    } catch (error: any) {
      setError(error.message);
      setIsLoading(false);
      setEmail("");
      setPassword("");
    }
  };

  return (
    <Flex width="full" align="center" justifyContent="center">
      <Box
        p={8}
        maxWidth="500px"
        borderWidth={1}
        borderRadius={8}
        boxShadow="lg"
      >
        <Box textAlign="center">
          <Heading> Sign Up </Heading>
        </Box>
        <Box my={4} textAlign="left">
          <form>
            {error && <ErrorMessage message={error} />}s
            <FormControl isRequired>
              <FormLabel> Email </FormLabel>
              <Input
                type="email"
                placeholder="user@todoapp.com"
                size="lg"
                onChange={(event) => setEmail(event.currentTarget.value)}
              />
            </FormControl>
            <FormControl isRequired mt={6}>
              <FormLabel> Password </FormLabel>
              <Input
                type="password"
                placeholder="Password"
                size="lg"
                onChange={(event) => setPassword(event.currentTarget.value)}
              />
            </FormControl>
            <Button
              variantColor="teal"
              variant="outline"
              width="full"
              mt={4}
              onClick={handleSubmit}
            >
              {isLoading ? (
                <CircularProgress isIndeterminate size="24px" color="teal" />
              ) : (
                "Sign Up"
              )}
            </Button>
          </form>
        </Box>
      </Box>
    </Flex>
  );
};

export default Signup;
