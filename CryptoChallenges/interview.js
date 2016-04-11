function calcSums(input, output, prodFront, index) {
  if (index == array.length) {
    return 1;
  }
  var prodBack = calcSums(input, output, prodFront * input[index], index + 1);
  output[index] = prodFront * prodBack;
  return prodBack * input[index];
}

function findLowest(arr, n) {
  var min = 0;
  var max = arr.length;
  if (arr[0] < arr[max - 1]) return 0;
  while (max - min > 1) {
    var idx = Math.floor(min + (max - min) / 2);
    if (arr[idx] < arr[min]) {
      max = idx;
    } else {
      min = idx;
    }
  }
  return min;
}

function findFirst(arr, n) {
  var min = 0;
  var max = arr.length;
  while (max - min > 1) {
    var idx = Math.floor(min + (max - min) / 2);
    if (arr[idx] >= n) {
      max = idx;
    } else {
      min = idx;
    }
  }
  return max < arr.length && arr[max] === n ? max : undefined;
}