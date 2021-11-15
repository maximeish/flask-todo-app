import React, { useEffect, useState } from "react";

interface Item {
  id: any;
  name: any;
}

const ToDo = () => {
  const [isFetching, setFetching] = useState(true);
  const [items, setItems] = useState<Item[]>([]);

  useEffect(() => {
    fetch("/fetch")
      .then((res) => res.json())
      .then((data) => {
        setTimeout(() => {
          setItems(data.items);
          setFetching(false);
        }, 3000);
      });
  }, []);

  return (
    <div>
      {isFetching ? (
        <div>Loading...</div>
      ) : (
        items.map((item) => <div key={item.id}>{item.name}</div>)
      )}
    </div>
  );
};

export default ToDo;
