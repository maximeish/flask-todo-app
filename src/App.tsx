import * as React from "react";
import {
  ChakraProvider,
  Box,
  Text,
  VStack,
  Grid,
  theme,
} from "@chakra-ui/react";
import ToDo from "./Todo";
import Authentication from "./auth";

export const App = () => (
  <ChakraProvider theme={theme}>
    <Box textAlign="center" fontSize="xl">
      <Grid minH="100vh" p={3}>
        <VStack spacing={4}>
          <Text fontSize="xl" fontWeight="bold">
            Todo App
          </Text>
          <Authentication />
          {/* <ToDo /> */}
        </VStack>
      </Grid>
    </Box>
  </ChakraProvider>
);
